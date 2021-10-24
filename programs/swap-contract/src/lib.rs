use std::{ io::Cursor, string::String, str::FromStr, result::Result as FnResult, convert::TryFrom };
use bytemuck::{ Pod, Zeroable };
use byte_slice_cast::*;
use num_enum::{ TryFromPrimitive, IntoPrimitive };
use switchboard_program;
use switchboard_program::{ FastRoundResultAccountData };
use anchor_lang::prelude::*;
use anchor_spl::token::{ self, MintTo, Transfer };
use solana_program::{
    sysvar, system_instruction, system_program,
    program::{ invoke, invoke_signed },
    account_info::AccountInfo,
    instruction::{ AccountMeta, Instruction },
    clock::Clock
};

extern crate slab_alloc;
use slab_alloc::{ SlabPageAlloc, CritMapHeader, CritMap, AnyNode, LeafNode, SlabVec, SlabTreeError };

extern crate decode_account;
use decode_account::parse_bpf_loader::{ parse_bpf_upgradeable_loader, BpfUpgradeableLoaderAccountType };

declare_id!("9RVS4RCT4bed1US9YudFZv9syKkfxfXg4odyV3kZLyjt");

pub const MAX_RBAC: u32 = 1024;

#[repr(u8)]
#[derive(PartialEq, Debug, Eq, Copy, Clone, TryFromPrimitive, IntoPrimitive)]
pub enum OracleType {
    NoOracle,
    Switchboard,
}

#[repr(u16)]
#[derive(PartialEq, Debug, Eq, Copy, Clone)]
pub enum DT { // Data types
    UserRBACMap,                 // CritMap
    UserRBAC,                    // Slabvec
}

#[repr(u32)]
#[derive(PartialEq, Debug, Eq, Copy, Clone, TryFromPrimitive)]
pub enum Role {             // Role-based access control:
    NetworkAdmin,           // Can manage RBAC for other users
    SwapAdmin,              // Can create swap exchanges and set parameters, rates, etc...
    SwapDeposit,            // Can deposit to swap contracts
    SwapWithdraw,           // Can withdraw from swap contracts
    SwapFees,               // Can receive fees from swaps
    NetAuthority,           // Valid network authority for merchant approvals
}

#[derive(Copy, Clone)]
#[repr(packed)]
pub struct UserRBAC {
    pub role: Role,
    pub free: u32,
}
unsafe impl Zeroable for UserRBAC {}
unsafe impl Pod for UserRBAC {}

impl UserRBAC {
    pub fn role(&self) -> Role {
        self.role
    }

    pub fn free(&self) -> u32 {
        self.free
    }

    pub fn set_free(&mut self, new_free: u32) {
        self.free = new_free
    }

    fn next_index(pt: &mut SlabPageAlloc, data_type: DT) -> FnResult<u32, ProgramError> {
        let svec = pt.header_mut::<SlabVec>(index_datatype(data_type));
        let free_top = svec.free_top();
        if free_top == 0 { // Empty free list
            return Ok(svec.next_index());
        }
        let free_index = free_top.checked_sub(1).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        let index_act = pt.index::<UserRBAC>(index_datatype(data_type), free_index as usize);
        let index_ptr = index_act.free();
        pt.header_mut::<SlabVec>(index_datatype(data_type)).set_free_top(index_ptr);
        Ok(free_index)
    }

    fn free_index(pt: &mut SlabPageAlloc, data_type: DT, idx: u32) -> ProgramResult {
        let free_top = pt.header::<SlabVec>(index_datatype(data_type)).free_top();
        pt.index_mut::<UserRBAC>(index_datatype(data_type), idx as usize).set_free(free_top);
        let new_top = idx.checked_add(1).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        pt.header_mut::<SlabVec>(index_datatype(data_type)).set_free_top(new_top);
        Ok(())
    }
}

#[inline]
fn index_datatype(data_type: DT) -> u16 {  // Maps only
    match data_type {
        DT::UserRBAC => DT::UserRBAC as u16,
        _ => { panic!("Invalid datatype") },
    }
}

#[inline]
fn map_len(data_type: DT) -> u32 {
    match data_type {
        DT::UserRBAC => MAX_RBAC,
        _ => 0,
    }
}

#[inline]
fn map_datatype(data_type: DT) -> u16 {  // Maps only
    match data_type {
        DT::UserRBAC => DT::UserRBACMap as u16,
        _ => { panic!("Invalid datatype") },
    }
}

#[inline]
fn map_get(pt: &mut SlabPageAlloc, data_type: DT, key: u128) -> Option<LeafNode> {
    let cm = CritMap { slab: pt, type_id: map_datatype(data_type), capacity: map_len(data_type) };
    let res = cm.get_key(key);
    match res {
        None => None,
        Some(res) => Some(res.clone()),
    }
}

#[inline]
fn map_insert(pt: &mut SlabPageAlloc, data_type: DT, node: &LeafNode) -> FnResult<(), SlabTreeError> {
    let mut cm = CritMap { slab: pt, type_id: map_datatype(data_type), capacity: map_len(data_type) };
    let res = cm.insert_leaf(node);
    match res {
        Err(SlabTreeError::OutOfSpace) => {
            //msg!("Atellix: Out of space...");
            return Err(SlabTreeError::OutOfSpace)
        },
        _  => Ok(())
    }
}

#[inline]
fn map_remove(pt: &mut SlabPageAlloc, data_type: DT, key: u128) -> FnResult<(), SlabTreeError> {
    let mut cm = CritMap { slab: pt, type_id: map_datatype(data_type), capacity: map_len(data_type) };
    cm.remove_by_key(key).ok_or(SlabTreeError::NotFound)?;
    Ok(())
}

fn has_role(acc_auth: &AccountInfo, role: Role, key: &Pubkey) -> ProgramResult {
    let auth_data: &mut [u8] = &mut acc_auth.try_borrow_mut_data()?;
    let rd = SlabPageAlloc::new(auth_data);
    let authhash: u128 = CritMap::bytes_hash([[role as u32].as_byte_slice(), key.as_ref()].concat().as_slice());
    let authrec = map_get(rd, DT::UserRBAC, authhash);
    if ! authrec.is_some() {
        return Err(ErrorCode::AccessDenied.into());
    }
    if authrec.unwrap().owner() != *key {
        msg!("User key does not match signer");
        return Err(ErrorCode::AccessDenied.into());
    }
    let urec = rd.index::<UserRBAC>(DT::UserRBAC as u16, authrec.unwrap().slot() as usize);
    if urec.role() != role {
        msg!("Role does not match");
        return Err(ErrorCode::AccessDenied.into());
    }
    Ok(())
}

fn verify_program_owner(program_id: &Pubkey, acc_prog: &AccountInfo, acc_pdat: &AccountInfo, acc_user: &AccountInfo) -> ProgramResult {
    if *acc_prog.key != *program_id {
        msg!("Program account is not this program");
        return Err(ErrorCode::AccessDenied.into());
    }
    //msg!("Verified program account");
    let data: &[u8] = &acc_prog.try_borrow_data()?;
    let res = parse_bpf_upgradeable_loader(data);
    if ! res.is_ok() {
        msg!("Failed to decode program");
        return Err(ErrorCode::AccessDenied.into());
    }
    let program_data = match res.unwrap() {
        BpfUpgradeableLoaderAccountType::Program(info) => info.program_data,
        _ => {
            msg!("Invalid program account type");
            return Err(ErrorCode::AccessDenied.into());
        },
    };
    if acc_pdat.key.to_string() != program_data {
        msg!("Program data address does not match");
        return Err(ErrorCode::AccessDenied.into());
    }
    //msg!("Verified program data account");
    let data2: &[u8] = &acc_pdat.try_borrow_data()?;
    let res2 = parse_bpf_upgradeable_loader(data2);
    if ! res2.is_ok() {
        msg!("Failed to decode program data");
        return Err(ErrorCode::AccessDenied.into());
    }
    let program_owner = match res2.unwrap() {
        BpfUpgradeableLoaderAccountType::ProgramData(info) => info.authority.unwrap(),
        _ => {
            msg!("Invalid program data account type");
            return Err(ErrorCode::AccessDenied.into());
        },
    };
    if acc_user.key.to_string() != program_owner {
        msg!("Root admin is not program owner");
        return Err(ErrorCode::AccessDenied.into());
    }
    //msg!("Verified program owner");
    Ok(())
}

fn verify_matching_accounts(left: &Pubkey, right: &Pubkey, error_msg: Option<String>) -> ProgramResult {
    if *left != *right {
        if error_msg.is_some() {
            msg!(error_msg.unwrap().as_str());
            msg!("Expected: {}", left.to_string());
            msg!("Received: {}", right.to_string());
        }
        return Err(ErrorCode::InvalidAccount.into());
    }
    Ok(())
}

#[program]
pub mod swap_contract {
    use super::*;
    pub fn initialize(ctx: Context<Initialize>,
        inp_root_size: u64,
        inp_root_rent: u64
    ) -> ProgramResult {
        let acc_prog = &ctx.accounts.program.to_account_info();
        let acc_pdat = &ctx.accounts.program_data.to_account_info();
        let acc_user = &ctx.accounts.program_admin.to_account_info();
        let acc_root = &ctx.accounts.root_data.to_account_info();
        let acc_auth = &ctx.accounts.auth_data.to_account_info();
        let acc_sys = &ctx.accounts.system_program.to_account_info();
        verify_program_owner(ctx.program_id, &acc_prog, &acc_pdat, &acc_user)?;
        let (data_account_address, bump_seed) = Pubkey::find_program_address(
            &[ctx.program_id.as_ref()],
            ctx.program_id,
        );
        if data_account_address != *acc_root.key {
            msg!("Invalid root data account");
            return Err(ErrorCode::InvalidDerivedAccount.into());
        }
        let account_signer_seeds: &[&[_]] = &[
            ctx.program_id.as_ref(),
            &[bump_seed],
        ];
        msg!("Atellix: Create root data account");
        invoke_signed(
            &system_instruction::create_account(
                acc_user.key,
                acc_root.key,
                inp_root_rent,
                inp_root_size,
                ctx.program_id
            ),
            &[
                acc_user.clone(),
                acc_root.clone(),
                acc_sys.clone(),
            ],
            &[account_signer_seeds],
        )?;

        let ra = RootData {
            root_authority: *acc_auth.key,
        };
        let mut root_data = acc_root.try_borrow_mut_data()?;
        let root_dst: &mut [u8] = &mut root_data;
        let mut root_crs = Cursor::new(root_dst);
        ra.try_serialize(&mut root_crs)?;

        let auth_data: &mut[u8] = &mut acc_auth.try_borrow_mut_data()?;
        let rd = SlabPageAlloc::new(auth_data);
        rd.setup_page_table();
        rd.allocate::<CritMapHeader, AnyNode>(DT::UserRBACMap as u16, MAX_RBAC as usize).expect("Failed to allocate");
        rd.allocate::<SlabVec, UserRBAC>(DT::UserRBAC as u16, MAX_RBAC as usize).expect("Failed to allocate");

        Ok(())
    }

    pub fn grant(ctx: Context<UpdateRBAC>,
        inp_root_nonce: u8,
        inp_role: u32,
    ) -> ProgramResult {
        let acc_admn = &ctx.accounts.program_admin.to_account_info(); // Program owner or network admin
        let acc_root = &ctx.accounts.root_data.to_account_info();
        let acc_auth = &ctx.accounts.auth_data.to_account_info();
        let acc_rbac = &ctx.accounts.rbac_user.to_account_info();

        // Check for NetworkAdmin authority
        let admin_role = has_role(&acc_auth, Role::NetworkAdmin, acc_admn.key);
        let mut program_owner: bool = false;
        if admin_role.is_err() {
            let acc_prog = &ctx.accounts.program.to_account_info();
            let acc_pdat = &ctx.accounts.program_data.to_account_info();
            verify_program_owner(ctx.program_id, &acc_prog, &acc_pdat, &acc_admn)?;
            program_owner = true;
        }

        // Verify specified role
        let role_item = Role::try_from_primitive(inp_role);
        if role_item.is_err() {
            msg!("Invalid role: {}", inp_role.to_string());
            return Err(ErrorCode::InvalidParameters.into());
        }
        let role = role_item.unwrap();
        if role == Role::NetworkAdmin && ! program_owner {
            msg!("Reserved for program owner");
            return Err(ErrorCode::AccessDenied.into());
        }

        // Verify not assigning roles to self
        if *acc_admn.key == *acc_rbac.key {
            msg!("Cannot grant roles to self");
            return Err(ErrorCode::AccessDenied.into());
        }

        // Verify program data
        let acc_root_expected = Pubkey::create_program_address(&[ctx.program_id.as_ref(), &[inp_root_nonce]], ctx.program_id)
            .map_err(|_| ErrorCode::InvalidDerivedAccount)?;
        verify_matching_accounts(acc_root.key, &acc_root_expected, Some(String::from("Invalid root data")))?;
        verify_matching_accounts(acc_auth.key, &ctx.accounts.root_data.root_authority, Some(String::from("Invalid root authority")))?;

        let auth_data: &mut[u8] = &mut acc_auth.try_borrow_mut_data()?;
        let rd = SlabPageAlloc::new(auth_data);
        let authhash: u128 = CritMap::bytes_hash([[role as u32].as_byte_slice(), acc_rbac.key.as_ref()].concat().as_slice());

        // Check if record exists
        let authrec = map_get(rd, DT::UserRBAC, authhash);
        if authrec.is_some() {
            msg!("Atellix: Role already active");
        } else {
            // Add new record
            let new_item = map_insert(rd, DT::UserRBAC, &LeafNode::new(authhash, 0, acc_rbac.key));
            if new_item.is_err() {
                msg!("Unable to insert role");
                return Err(ErrorCode::InternalError.into());
            }
            let rbac_idx = UserRBAC::next_index(rd, DT::UserRBAC)?;
            let mut cm = CritMap { slab: rd, type_id: map_datatype(DT::UserRBAC), capacity: map_len(DT::UserRBAC) };
            cm.get_key_mut(authhash).unwrap().set_slot(rbac_idx);
            *rd.index_mut(DT::UserRBAC as u16, rbac_idx as usize) = UserRBAC { role: role, free: 0 };
            msg!("Atellix: Role granted");
        }
        Ok(())
    }

    pub fn revoke(ctx: Context<UpdateRBAC>,
        inp_root_nonce: u8,
        inp_role: u32,
    ) -> ProgramResult {
        let acc_admn = &ctx.accounts.program_admin.to_account_info(); // Program owner or network admin
        let acc_root = &ctx.accounts.root_data.to_account_info();
        let acc_auth = &ctx.accounts.auth_data.to_account_info();
        let acc_rbac = &ctx.accounts.rbac_user.to_account_info();

        // Check for NetworkAdmin authority
        let admin_role = has_role(&acc_auth, Role::NetworkAdmin, acc_admn.key);
        let mut program_owner: bool = false;
        if admin_role.is_err() {
            let acc_prog = &ctx.accounts.program.to_account_info();
            let acc_pdat = &ctx.accounts.program_data.to_account_info();
            verify_program_owner(ctx.program_id, &acc_prog, &acc_pdat, &acc_admn)?;
            program_owner = true;
        }

        // Verify specified role
        let role_item = Role::try_from_primitive(inp_role);
        if role_item.is_err() {
            msg!("Invalid role: {}", inp_role.to_string());
            return Err(ErrorCode::InvalidParameters.into());
        }
        let role = role_item.unwrap();
        if role == Role::NetworkAdmin && ! program_owner {
            msg!("Reserved for program owner");
            return Err(ErrorCode::AccessDenied.into());
        }

        // Verify program data
        let acc_root_expected = Pubkey::create_program_address(&[ctx.program_id.as_ref(), &[inp_root_nonce]], ctx.program_id)
            .map_err(|_| ErrorCode::InvalidDerivedAccount)?;
        verify_matching_accounts(acc_root.key, &acc_root_expected, Some(String::from("Invalid root data")))?;
        verify_matching_accounts(acc_auth.key, &ctx.accounts.root_data.root_authority, Some(String::from("Invalid root authority")))?;

        let auth_data: &mut[u8] = &mut acc_auth.try_borrow_mut_data()?;
        let rd = SlabPageAlloc::new(auth_data);
        let authhash: u128 = CritMap::bytes_hash([[role as u32].as_byte_slice(), acc_rbac.key.as_ref()].concat().as_slice());

        // Check if record exists
        let authrec = map_get(rd, DT::UserRBAC, authhash);
        if authrec.is_some() {
            map_remove(rd, DT::UserRBAC, authhash).or(Err(ProgramError::from(ErrorCode::InternalError)))?;
            UserRBAC::free_index(rd, DT::UserRBAC, authrec.unwrap().slot())?;
            msg!("Atellix: Role revoked");
        } else {
            msg!("Atellix: Role not found");
        }
        Ok(())
    }

    pub fn approve_token(ctx: Context<ApproveToken>,
        inp_root_nonce: u8,         // RootData nonce
        inp_tinf_nonce: u8,         // Token Info nonce
        inp_tokn_nonce: u8,         // Associated token nonce
        inp_tinf_rent: u64,         // Token Info rent
        inp_tinf_size: u64,         // Token Info size
        inp_decimals: u8,           // Token decimals
    ) -> ProgramResult {
        let acc_admn = &ctx.accounts.swap_admin.to_account_info(); // Swap admin
        let acc_root = &ctx.accounts.root_data.to_account_info();
        let acc_auth = &ctx.accounts.auth_data.to_account_info();
        let acc_mint = &ctx.accounts.token_mint.to_account_info();
        let acc_info = &ctx.accounts.token_info.to_account_info();
        let acc_prog = &ctx.accounts.token_program.to_account_info();
        let acc_asct = &ctx.accounts.asc_program.to_account_info();
        let acc_tokn = &ctx.accounts.swap_token.to_account_info();
        let acc_rent = &ctx.accounts.system_rent.to_account_info();
        let acc_sys = &ctx.accounts.system_program.to_account_info();

        // Verify program data
        let acc_root_expected = Pubkey::create_program_address(&[ctx.program_id.as_ref(), &[inp_root_nonce]], ctx.program_id)
            .map_err(|_| ErrorCode::InvalidDerivedAccount)?;
        verify_matching_accounts(acc_root.key, &acc_root_expected, Some(String::from("Invalid root data")))?;
        verify_matching_accounts(acc_auth.key, &ctx.accounts.root_data.root_authority, Some(String::from("Invalid root authority")))?;

        let admin_role = has_role(&acc_auth, Role::SwapAdmin, acc_admn.key);
        if admin_role.is_err() {
            msg!("No swap admin role");
            return Err(ErrorCode::AccessDenied.into());
        }

        let acc_tinf_expected = Pubkey::create_program_address(&[acc_mint.key.as_ref(), &[inp_tinf_nonce]], ctx.program_id)
            .map_err(|_| ErrorCode::InvalidDerivedAccount)?;
        verify_matching_accounts(acc_info.key, &acc_tinf_expected, Some(String::from("Invalid token info")))?;

        // Verify swap associated token
        let spl_token: Pubkey = Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap();
        let asc_token: Pubkey = Pubkey::from_str("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL").unwrap();
        let derived_key = Pubkey::create_program_address(
            &[
                &acc_root.key.to_bytes(),
                &spl_token.to_bytes(),
                &acc_mint.key.to_bytes(),
                &[inp_tokn_nonce]
            ],
            &asc_token
        ).map_err(|_| ErrorCode::InvalidDerivedAccount)?;
        if derived_key != *acc_tokn.key {
            msg!("Invalid token account");
            return Err(ErrorCode::InvalidDerivedAccount.into());
        }

        if asc_token != *acc_asct.key {
            msg!("Invalid associated token program id");
            return Err(ErrorCode::InvalidAccount.into());
        }

        // Fund associated token account
        msg!("Atellix: Create associated token account");
        let instr = Instruction {
            program_id: asc_token,
            accounts: vec![
                AccountMeta::new(*acc_admn.key, true),
                AccountMeta::new(*acc_tokn.key, false),
                AccountMeta::new_readonly(*acc_root.key, false),
                AccountMeta::new_readonly(*acc_mint.key, false),
                AccountMeta::new_readonly(solana_program::system_program::id(), false),
                AccountMeta::new_readonly(spl_token, false),
                AccountMeta::new_readonly(sysvar::rent::id(), false),
            ],
            data: vec![],
        };
        invoke(
            &instr,
            &[
                acc_admn.clone(),
                acc_tokn.clone(),
                acc_root.clone(),
                acc_mint.clone(),
                acc_sys.clone(),
                acc_prog.clone(),
                acc_rent.clone(),
            ]
        )?;

        msg!("Atellix: Create token info account");
        let account_signer_seeds: &[&[_]] = &[
            acc_mint.key.as_ref(),
            &[inp_tinf_nonce],
        ];
        invoke_signed(
            &system_instruction::create_account(
                acc_admn.key,
                acc_info.key,
                inp_tinf_rent,
                inp_tinf_size,
                ctx.program_id
            ),
            &[
                acc_admn.clone(),
                acc_info.clone(),
                acc_sys.clone(),
            ],
            &[account_signer_seeds],
        )?;

        let clock = Clock::get()?;
        let ra = TokenInfo {
            mint: *acc_mint.key,
            decimals: inp_decimals,
            amount: 0,
            token_tx_count: 0,
            slot: clock.slot,
        };
        let mut tk_data = acc_info.try_borrow_mut_data()?;
        let tk_dst: &mut [u8] = &mut tk_data;
        let mut tk_crs = Cursor::new(tk_dst);
        ra.try_serialize(&mut tk_crs)?;

        Ok(())
    }

    pub fn create_swap(ctx: Context<CreateSwap>,
        inp_root_nonce: u8,         // RootData nonce
        inp_oracle_rates: bool,     // Use oracle for swap rates
        inp_oracle_inverse: bool,   // Inverse the oracle for "Buy" orders
        inp_oracle_verify: bool,    // Use oracle to verify price range (to check peg stability on stablecoins)
        inp_oracle_type: u8,        // Use oracle type
        inp_verify_min: u64,        // Minimum of price range (0 for unused)
        inp_verify_max: u64,        // Maximum of price range (0 for unused)
        inp_swap_rate: u64,         // Swap rate
        inp_base_rate: u64,         // Base rate
        inp_fees_inbound: bool,     // Take fees from inbound token (alternatively use the outbound token)
        inp_fees_bps: u32,          // Fees basis points
    ) -> ProgramResult {
        let acc_admn = &ctx.accounts.swap_admin.to_account_info(); // Swap admin
        let acc_swap = &ctx.accounts.swap_data.to_account_info(); 
        let acc_root = &ctx.accounts.root_data.to_account_info();
        let acc_auth = &ctx.accounts.auth_data.to_account_info();
        let acc_inb = &ctx.accounts.inb_info.to_account_info();
        let acc_out = &ctx.accounts.out_info.to_account_info();

        // Verify program data
        let acc_root_expected = Pubkey::create_program_address(&[ctx.program_id.as_ref(), &[inp_root_nonce]], ctx.program_id)
            .map_err(|_| ErrorCode::InvalidDerivedAccount)?;
        verify_matching_accounts(acc_root.key, &acc_root_expected, Some(String::from("Invalid root data")))?;
        verify_matching_accounts(acc_auth.key, &ctx.accounts.root_data.root_authority, Some(String::from("Invalid root authority")))?;

        let admin_role = has_role(&acc_auth, Role::SwapAdmin, acc_admn.key);
        if admin_role.is_err() {
            msg!("No swap admin role");
            return Err(ErrorCode::AccessDenied.into());
        }

        if ctx.accounts.inb_info.mint == ctx.accounts.out_info.mint {
            msg!("Both tokens have the same mint");
            return Err(ErrorCode::InvalidParameters.into());
        }

        OracleType::try_from(inp_oracle_type).map_err(|_| {
            msg!("Invalid oracle type");
            ErrorCode::InvalidParameters
        })?;
        let mut oracle: Pubkey = Pubkey::default();
        if inp_oracle_rates || inp_oracle_verify {
            let acc_orac = ctx.remaining_accounts.get(0).unwrap();
            oracle = *acc_orac.key;
        }

        let clock = Clock::get()?;
        let sw = SwapData {
            active: true,
            slot: clock.slot,
            merchant_only: false,
            oracle_data: oracle,
            oracle_type: inp_oracle_type,
            oracle_rates: inp_oracle_rates,
            oracle_inverse: inp_oracle_inverse,
            oracle_verify: inp_oracle_verify,
            oracle_verify_min: inp_verify_min,
            oracle_verify_max: inp_verify_max,
            rate_swap: inp_swap_rate,
            rate_base: inp_base_rate,
            inb_token_info: *acc_inb.key,
            inb_token_tx: 0,
            out_token_info: *acc_out.key,
            out_token_tx: 0,
            fees_inbound: inp_fees_inbound,
            fees_token: *ctx.accounts.fees_token.to_account_info().key,
            fees_bps: inp_fees_bps,
            swap_tx_count: 0,
            swap_inb_tokens: 0,
            swap_out_tokens: 0,
        };
        let mut sw_data = acc_swap.try_borrow_mut_data()?;
        let sw_dst: &mut [u8] = &mut sw_data;
        let mut sw_crs = Cursor::new(sw_dst);
        sw.try_serialize(&mut sw_crs)?;

        Ok(())
    }

    pub fn mint_deposit(ctx: Context<MintDeposit>,
        inp_root_nonce: u8,         // RootData nonce
        inp_tinf_nonce: u8,         // Token Info nonce
        inp_tokn_nonce: u8,         // Associated token nonce
        inp_amount: u64,            // Amount to mint
    ) -> ProgramResult {
        let acc_admn = &ctx.accounts.swap_admin.to_account_info(); // Swap admin
        let acc_tadm = &ctx.accounts.token_admin.to_account_info(); // Token mint or transfer authority
        let acc_root = &ctx.accounts.root_data.to_account_info();
        let acc_auth = &ctx.accounts.auth_data.to_account_info();
        let acc_info = &ctx.accounts.token_info.to_account_info();
        let acc_mint = &ctx.accounts.token_mint.to_account_info();
        let acc_prog = &ctx.accounts.token_program.to_account_info();
        let acc_tokn = &ctx.accounts.swap_token.to_account_info();
        
        // Verify program data
        let acc_root_expected = Pubkey::create_program_address(&[ctx.program_id.as_ref(), &[inp_root_nonce]], ctx.program_id)
            .map_err(|_| ErrorCode::InvalidDerivedAccount)?;
        verify_matching_accounts(acc_root.key, &acc_root_expected, Some(String::from("Invalid root data")))?;
        verify_matching_accounts(acc_auth.key, &ctx.accounts.root_data.root_authority, Some(String::from("Invalid root authority")))?;

        let admin_role = has_role(&acc_auth, Role::SwapDeposit, acc_admn.key);
        if admin_role.is_err() {
            msg!("No swap deposit role");
            return Err(ErrorCode::AccessDenied.into());
        }
        let acc_tinf_expected = Pubkey::create_program_address(&[acc_mint.key.as_ref(), &[inp_tinf_nonce]], ctx.program_id)
            .map_err(|_| ErrorCode::InvalidDerivedAccount)?;
        verify_matching_accounts(acc_info.key, &acc_tinf_expected, Some(String::from("Invalid token info")))?;
        verify_matching_accounts(acc_mint.key, &ctx.accounts.token_info.mint, Some(String::from("Invalid token mint")))?;

        // Verify swap associated token
        let spl_token: Pubkey = Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap();
        let asc_token: Pubkey = Pubkey::from_str("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL").unwrap();
        let derived_key = Pubkey::create_program_address(
            &[
                &acc_root.key.to_bytes(),
                &spl_token.to_bytes(),
                &acc_mint.key.to_bytes(),
                &[inp_tokn_nonce]
            ],
            &asc_token
        ).map_err(|_| ErrorCode::InvalidDerivedAccount)?;
        if derived_key != *acc_tokn.key {
            msg!("Invalid token account");
            return Err(ErrorCode::InvalidDerivedAccount.into());
        }

        //msg!("Atellix: Attempt mint deposit: {}", inp_amount.to_string());
        let cpi_accounts = MintTo {
            mint: acc_mint.clone(),
            to: acc_tokn.clone(),
            authority: acc_tadm.clone(),
        };
        let cpi_program = acc_prog.clone();
        let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);
        token::mint_to(cpi_ctx, inp_amount)?;

        let clock = Clock::get()?;
        ctx.accounts.token_info.amount = ctx.accounts.token_info.amount.checked_add(inp_amount).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        ctx.accounts.token_info.token_tx_count = ctx.accounts.token_info.token_tx_count.checked_add(1).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        ctx.accounts.token_info.slot = clock.slot;

        //msg!("Atellix: New token amount: {}", ctx.accounts.token_info.amount.to_string());
        emit!(TransferEvent {
            event_hash: 86124742241384372364379956883437878997, // solana/program/atx-swap-contract/deposit_mint
            slot: clock.slot,
            user: acc_admn.key(),
            token_info: acc_info.key(),
            token_acct: Pubkey::default(),
            deposit: true,
            transfer: true,
            amount: inp_amount,
            new_total: ctx.accounts.token_info.amount,
            token_tx: ctx.accounts.token_info.token_tx_count,
        });

        Ok(())
    }

    pub fn deposit(ctx: Context<TransferDeposit>,
        inp_root_nonce: u8,         // RootData nonce
        inp_tinf_nonce: u8,         // Token Info nonce
        inp_tokn_nonce: u8,         // Associated token nonce
        inp_amount: u64,            // Amount to mint
    ) -> ProgramResult {
        let acc_admn = &ctx.accounts.swap_admin.to_account_info(); // Swap admin
        let acc_tadm = &ctx.accounts.token_admin.to_account_info(); // Token mint or transfer authority
        let acc_root = &ctx.accounts.root_data.to_account_info();
        let acc_auth = &ctx.accounts.auth_data.to_account_info();
        let acc_info = &ctx.accounts.token_info.to_account_info();
        let acc_mint = &ctx.accounts.token_mint.to_account_info();
        let acc_tsrc = &ctx.accounts.token_src.to_account_info();
        let acc_prog = &ctx.accounts.token_program.to_account_info();
        let acc_tokn = &ctx.accounts.swap_token.to_account_info();
        
        // Verify program data
        let acc_root_expected = Pubkey::create_program_address(&[ctx.program_id.as_ref(), &[inp_root_nonce]], ctx.program_id)
            .map_err(|_| ErrorCode::InvalidDerivedAccount)?;
        verify_matching_accounts(acc_root.key, &acc_root_expected, Some(String::from("Invalid root data")))?;
        verify_matching_accounts(acc_auth.key, &ctx.accounts.root_data.root_authority, Some(String::from("Invalid root authority")))?;

        let admin_role = has_role(&acc_auth, Role::SwapDeposit, acc_admn.key);
        if admin_role.is_err() {
            msg!("No swap deposit role");
            return Err(ErrorCode::AccessDenied.into());
        }
        let acc_tinf_expected = Pubkey::create_program_address(&[acc_mint.key.as_ref(), &[inp_tinf_nonce]], ctx.program_id)
            .map_err(|_| ErrorCode::InvalidDerivedAccount)?;
        verify_matching_accounts(acc_info.key, &acc_tinf_expected, Some(String::from("Invalid token info")))?;
        verify_matching_accounts(acc_mint.key, &ctx.accounts.token_info.mint, Some(String::from("Invalid token mint")))?;

        // Verify swap associated token
        let spl_token: Pubkey = Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap();
        let asc_token: Pubkey = Pubkey::from_str("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL").unwrap();
        let derived_key = Pubkey::create_program_address(
            &[
                &acc_root.key.to_bytes(),
                &spl_token.to_bytes(),
                &acc_mint.key.to_bytes(),
                &[inp_tokn_nonce]
            ],
            &asc_token
        ).map_err(|_| ErrorCode::InvalidDerivedAccount)?;
        if derived_key != *acc_tokn.key {
            msg!("Invalid token account");
            return Err(ErrorCode::InvalidDerivedAccount.into());
        }

        //msg!("Atellix: Attempt transfer deposit: {}", inp_amount.to_string());
        let cpi_accounts = Transfer {
            from: acc_tsrc.clone(),
            to: acc_tokn.clone(),
            authority: acc_tadm.clone(),
        };
        let cpi_program = acc_prog.clone();
        let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);
        token::transfer(cpi_ctx, inp_amount)?;

        let clock = Clock::get()?;
        ctx.accounts.token_info.amount = ctx.accounts.token_info.amount.checked_add(inp_amount).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        ctx.accounts.token_info.token_tx_count = ctx.accounts.token_info.token_tx_count.checked_add(1).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        ctx.accounts.token_info.slot = clock.slot;

        //msg!("Atellix: New token amount: {}", ctx.accounts.token_info.amount.to_string());
        emit!(TransferEvent {
            event_hash: 46880124277820728117333064135303940398, // solana/program/atx-swap-contract/deposit_transfer
            slot: clock.slot,
            user: acc_admn.key(),
            token_info: acc_info.key(),
            token_acct: acc_tsrc.key(),
            deposit: true,
            transfer: false,
            amount: inp_amount,
            new_total: ctx.accounts.token_info.amount,
            token_tx: ctx.accounts.token_info.token_tx_count,
        });

        Ok(())
    }

    pub fn withdraw(ctx: Context<Withdraw>,
        inp_root_nonce: u8,         // RootData nonce
        inp_tinf_nonce: u8,         // Token Info nonce
        inp_tokn_nonce: u8,         // Associated token nonce
        inp_amount: u64,            // Amount to mint
    ) -> ProgramResult {
        let acc_admn = &ctx.accounts.swap_admin.to_account_info(); // Swap admin
        let acc_root = &ctx.accounts.root_data.to_account_info();
        let acc_auth = &ctx.accounts.auth_data.to_account_info();
        let acc_info = &ctx.accounts.token_info.to_account_info();
        let acc_mint = &ctx.accounts.token_mint.to_account_info();
        let acc_tdst = &ctx.accounts.token_dst.to_account_info();
        let acc_prog = &ctx.accounts.token_program.to_account_info();
        let acc_tokn = &ctx.accounts.swap_token.to_account_info();
        
        // Verify program data
        let acc_root_expected = Pubkey::create_program_address(&[ctx.program_id.as_ref(), &[inp_root_nonce]], ctx.program_id)
            .map_err(|_| ErrorCode::InvalidDerivedAccount)?;
        verify_matching_accounts(acc_root.key, &acc_root_expected, Some(String::from("Invalid root data")))?;
        verify_matching_accounts(acc_auth.key, &ctx.accounts.root_data.root_authority, Some(String::from("Invalid root authority")))?;

        let admin_role = has_role(&acc_auth, Role::SwapWithdraw, acc_admn.key);
        if admin_role.is_err() {
            msg!("No swap withdraw role");
            return Err(ErrorCode::AccessDenied.into());
        }
        let acc_tinf_expected = Pubkey::create_program_address(&[acc_mint.key.as_ref(), &[inp_tinf_nonce]], ctx.program_id)
            .map_err(|_| ErrorCode::InvalidDerivedAccount)?;
        verify_matching_accounts(acc_info.key, &acc_tinf_expected, Some(String::from("Invalid token info")))?;
        verify_matching_accounts(acc_mint.key, &ctx.accounts.token_info.mint, Some(String::from("Invalid token mint")))?;

        // Verify swap associated token
        let spl_token: Pubkey = Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap();
        let asc_token: Pubkey = Pubkey::from_str("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL").unwrap();
        let derived_key = Pubkey::create_program_address(
            &[
                &acc_root.key.to_bytes(),
                &spl_token.to_bytes(),
                &acc_mint.key.to_bytes(),
                &[inp_tokn_nonce]
            ],
            &asc_token
        ).map_err(|_| ErrorCode::InvalidDerivedAccount)?;
        if derived_key != *acc_tokn.key {
            msg!("Invalid token account");
            return Err(ErrorCode::InvalidDerivedAccount.into());
        }

        msg!("Atellix: Attempt withdraw: {}", inp_amount.to_string());
        let cpi_accounts = Transfer {
            from: acc_tokn.clone(),
            to: acc_tdst.clone(),
            authority: ctx.accounts.root_data.to_account_info(),
        };
        let cpi_program = acc_prog.clone();
        let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);
        token::transfer(cpi_ctx, inp_amount)?;

        let clock = Clock::get()?;
        ctx.accounts.token_info.amount = ctx.accounts.token_info.amount.checked_sub(inp_amount).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        ctx.accounts.token_info.token_tx_count = ctx.accounts.token_info.token_tx_count.checked_add(1).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        ctx.accounts.token_info.slot = clock.slot;

        msg!("Atellix: New token amount: {}", ctx.accounts.token_info.amount.to_string());
        emit!(TransferEvent {
            event_hash: 107672350896016821143127613886765419987, // solana/program/atx-swap-contract/withdraw
            slot: clock.slot,
            user: acc_admn.key(),
            token_info: acc_info.key(),
            token_acct: acc_tdst.key(),
            deposit: false,
            transfer: true,
            amount: inp_amount,
            new_total: ctx.accounts.token_info.amount,
            token_tx: ctx.accounts.token_info.token_tx_count,
        });

        Ok(())
    }

    pub fn swap(ctx: Context<Swap>,
        inp_root_nonce: u8,
        inp_inb_nonce: u8,          // Associated token nonce for inb_token_dst
        inp_out_nonce: u8,          // Associated token nonce for out_token_src
        inp_is_buy: bool,           // Is "Buy" order, otherwise its a "Sell" order
                                    // Buy orders receive X out tokens, Sell orders send X inb tokens
        inp_tokens: u64,            // Number of tokens to send/receive (X tokens)
    ) -> ProgramResult {
        let acc_root = &ctx.accounts.root_data.to_account_info();
        let acc_auth = &ctx.accounts.auth_data.to_account_info();

        // Verify program data
        let acc_root_expected = Pubkey::create_program_address(&[ctx.program_id.as_ref(), &[inp_root_nonce]], ctx.program_id)
            .map_err(|_| ErrorCode::InvalidDerivedAccount)?;
        verify_matching_accounts(acc_root.key, &acc_root_expected, Some(String::from("Invalid root data")))?;
        verify_matching_accounts(acc_auth.key, &ctx.accounts.root_data.root_authority, Some(String::from("Invalid root authority")))?;

        // TODO: verify merchants with net authority if needed

        // Verify fees token
        verify_matching_accounts(&sw.fees_token, ctx.accounts.fees_token.to_account_info().key, Some(String::from("Invalid fees token")))?;

        // Verify swap token info
        let acc_inb = &ctx.accounts.inb_info.to_account_info();
        let acc_out = &ctx.accounts.out_info.to_account_info();
        let sw = &ctx.accounts.swap_data;
        if ! sw.active {
            msg!("Inactive swap");
            return Err(ErrorCode::AccessDenied.into());
        }
        verify_matching_accounts(&sw.inb_token_info, acc_inb.key, Some(String::from("Invalid inbound token info")))?;
        verify_matching_accounts(&sw.out_token_info, acc_out.key, Some(String::from("Invalid outbound token info")))?;
        let inb_info = &mut ctx.accounts.inb_info;
        let out_info = &mut ctx.accounts.out_info;

        let acc_inb_token_src = ctx.accounts.inb_token_src.to_account_info();
        let acc_inb_token_dst = ctx.accounts.inb_token_dst.to_account_info();
        let acc_out_token_src = ctx.accounts.out_token_src.to_account_info();
        let acc_out_token_dst = ctx.accounts.out_token_dst.to_account_info();

        // Verify inbound dest associated token
        let spl_token: Pubkey = Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap();
        let asc_token: Pubkey = Pubkey::from_str("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL").unwrap();
        let derived_key_in = Pubkey::create_program_address(
            &[
                &acc_root.key.to_bytes(),
                &spl_token.to_bytes(),
                &inb_info.mint.to_bytes(),
                &[inp_inb_nonce]
            ],
            &asc_token
        ).map_err(|_| ErrorCode::InvalidDerivedAccount)?;
        if derived_key_in != *acc_inb_token_dst.key {
            msg!("Invalid inbound token destination account");
            return Err(ErrorCode::InvalidDerivedAccount.into());
        }

        // Verify outbound src associated token
        let derived_key_out = Pubkey::create_program_address(
            &[
                &acc_root.key.to_bytes(),
                &spl_token.to_bytes(),
                &out_info.mint.to_bytes(),
                &[inp_out_nonce]
            ],
            &asc_token
        ).map_err(|_| ErrorCode::InvalidDerivedAccount)?;
        if derived_key_out != *acc_out_token_src.key {
            msg!("Invalid outbound token source account");
            return Err(ErrorCode::InvalidDerivedAccount.into());
        }

        let mut oracle_log_key: Pubkey = Pubkey::default();
        let mut oracle_log_val: u128 = 0;
        let mut oracle_log_inuse: bool = false;
        if sw.oracle_rates || sw.oracle_verify {
            let acc_orac = ctx.remaining_accounts.get(0).unwrap();
            verify_matching_accounts(acc_orac.key, &sw.oracle_data, Some(String::from("Invalid oracle data")))?;
            oracle_log_key = *acc_orac.key;
            oracle_log_inuse = true;
        }

        /*if sw.oracle_verify { // Check for valid oracle range before proceeding
        }*/

        msg!("Atellix: Tokens verified ready to swap");
        let mut tokens_inb: u64;
        let mut tokens_out: u64;
        
        if sw.oracle_rates {
            msg!("Atellix: Use oracle rates");
            tokens_inb = inp_tokens;
            let acc_orac = ctx.remaining_accounts.get(0).unwrap();
            let oracle_type = OracleType::try_from(sw.oracle_type).unwrap();
            let oracle_val: f64;
            if oracle_type == OracleType::Switchboard {
                let feed_data = FastRoundResultAccountData::deserialize(&acc_orac.try_borrow_data()?).unwrap();
                oracle_val = feed_data.result.result;
            } else {
                msg!("Invalid oracle type");
                return Err(ErrorCode::InternalError.into());
            }
            msg!("Atellix: Oracle value: {}", oracle_val.to_string());
            let adjust_u: u32 = 8;
            let adjust_i: i32 = 8;
            let base_u: u128 = 10;
            let base_f: f64 = 10.0;
            let oracle_adj: f64 = oracle_val * base_f.powi(adjust_i);
            let oracle_scl: u128 = oracle_adj as u128;
            oracle_log_val = oracle_scl; // Value times 10^8 in u128
            let mut calc_inp: u128 = tokens_inb as u128;
            let mut calc_dnm: u128;
            let calc_out: u128;
            if sw.oracle_inverse {
                if inp_is_buy {         // Buy order (price in outbound tokens)
                    msg!("Atellix: Buy order (oracle, inverse)");
                    calc_inp = calc_inp.checked_mul(sw.rate_swap as u128).ok_or(ProgramError::from(ErrorCode::Overflow))?;
                    calc_inp = calc_inp.checked_mul(oracle_scl).ok_or(ProgramError::from(ErrorCode::Overflow))?;
                    calc_dnm = sw.rate_base as u128;
                    calc_dnm = calc_dnm.checked_mul(base_u.pow(adjust_u)).ok_or(ProgramError::from(ErrorCode::Overflow))?;
                    calc_out = calc_inp.checked_div(calc_dnm).ok_or(ProgramError::from(ErrorCode::Overflow))?;
                } else {                // Sell order (price in inbound tokens)
                    msg!("Atellix: Sell order (oracle, inverse)");
                    calc_inp = calc_inp.checked_mul(sw.rate_base as u128).ok_or(ProgramError::from(ErrorCode::Overflow))?;
                    calc_inp = calc_inp.checked_mul(base_u.pow(adjust_u)).ok_or(ProgramError::from(ErrorCode::Overflow))?;
                    calc_dnm = sw.rate_swap as u128;
                    calc_dnm = calc_dnm.checked_mul(oracle_scl).ok_or(ProgramError::from(ErrorCode::Overflow))?;
                    calc_out = calc_inp.checked_div(calc_dnm).ok_or(ProgramError::from(ErrorCode::Overflow))?;
                }
            } else {
                if inp_is_buy {         // Buy order (price in outbound tokens)
                    msg!("Atellix: Buy order (oracle)");
                    calc_inp = calc_inp.checked_mul(sw.rate_swap as u128).ok_or(ProgramError::from(ErrorCode::Overflow))?;
                    calc_inp = calc_inp.checked_mul(base_u.pow(adjust_u)).ok_or(ProgramError::from(ErrorCode::Overflow))?;
                    calc_dnm = sw.rate_base as u128;
                    calc_dnm = calc_dnm.checked_mul(oracle_scl).ok_or(ProgramError::from(ErrorCode::Overflow))?;
                    calc_out = calc_inp.checked_div(calc_dnm).ok_or(ProgramError::from(ErrorCode::Overflow))?;
                } else {                // Sell order (price in inbound tokens)
                    msg!("Atellix: Sell order (oracle)");
                    calc_inp = calc_inp.checked_mul(sw.rate_base as u128).ok_or(ProgramError::from(ErrorCode::Overflow))?;
                    calc_inp = calc_inp.checked_mul(oracle_scl).ok_or(ProgramError::from(ErrorCode::Overflow))?;
                    calc_dnm = sw.rate_swap as u128;
                    calc_dnm = calc_dnm.checked_mul(base_u.pow(adjust_u)).ok_or(ProgramError::from(ErrorCode::Overflow))?;
                    calc_out = calc_inp.checked_div(calc_dnm).ok_or(ProgramError::from(ErrorCode::Overflow))?;
                }
            }
            if calc_out > u64::MAX as u128 {
                return Err(ErrorCode::Overflow.into());
            }
            tokens_out = calc_out as u64;
        } else if sw.rate_swap == sw.rate_base { // Symmetrical swap
            msg!("Atellix: Symmetrical swap");
            tokens_inb = inp_tokens;
            tokens_out = inp_tokens;
        } else {
            msg!("Atellix: Ratio swap");
            if inp_is_buy {         // Buy order (price in outbound tokens)
                msg!("Atellix: Buy order");
                tokens_out = inp_tokens;
                tokens_inb = tokens_out.checked_mul(sw.rate_swap).ok_or(ProgramError::from(ErrorCode::Overflow))?;
                tokens_inb = tokens_inb.checked_div(sw.rate_base).ok_or(ProgramError::from(ErrorCode::Overflow))?;
            } else {                // Sell order (price in inbound tokens)
                msg!("Atellix: Sell order");
                tokens_inb = inp_tokens;
                tokens_out = tokens_inb.checked_mul(sw.rate_base).ok_or(ProgramError::from(ErrorCode::Overflow))?;
                tokens_out = tokens_out.checked_div(sw.rate_swap).ok_or(ProgramError::from(ErrorCode::Overflow))?;
            }
        }

        // Calculate fees
        let mut fees_net: u64 = 0;
        if sw.fees_bps > 0 {
            let fees_input: u64;
            if sw.fees_inbound {
                fees_input = tokens_inb;
            } else {
                fees_input = tokens_out;
            }
            fees_net = fees_input.checked_mul(sw.fees_bps).ok_or(ProgramError::from(ErrorCode::Overflow))?;
            fees_net = fees_net.checked_div(10000).ok_or(ProgramError::from(ErrorCode::Overflow))?;
            msg!("Atellix: Fees Net: {}", fees_net.to_string());
            if inp_is_buy {
                tokens_inb = tokens_inb.checked_add(fees_net).ok_or(ProgramError::from(ErrorCode::Overflow))?;
            } else {
                tokens_out = tokens_out.checked_sub(fees_net).ok_or(ProgramError::from(ErrorCode::Overflow))?;
            }
        }

        msg!("Atellix: Inbound Tokens: {}", tokens_inb.to_string());
        msg!("Atellix: Outbound Tokens: {}", tokens_out.to_string());
        if sw.fees_inbound {
            msg!("Atellix: Fees Inbound Tokens: {}", fees_net.to_string());
        } else {
            msg!("Atellix: Fees Outbound Tokens: {}", fees_net.to_string());
        }

        msg!("Atellix: Available Outbound Tokens: {}", out_info.amount.to_string());
        inb_info.amount = inb_info.amount.checked_add(tokens_inb).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        out_info.amount = out_info.amount.checked_sub(tokens_out).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        if ! sw.fees_inbound {
            out_info.amount = out_info.amount.checked_sub(fees_net).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        }

        msg!("Atellix: New Inbound Amount: {}", inb_info.amount.to_string());
        msg!("Atellix: New Outbound Amount: {}", out_info.amount.to_string());

        let in_accounts = Transfer {
            from: acc_inb_token_src,
            to: acc_inb_token_dst,
            authority: ctx.accounts.swap_user.to_account_info(),
        };
        let cpi_prog1 = ctx.accounts.token_program.clone();
        let in_ctx = CpiContext::new(cpi_prog1, in_accounts);
        msg!("Atellix: Attempt Inbound Transfer");
        token::transfer(in_ctx, tokens_inb)?;

        let out_seeds = &[
            ctx.program_id.as_ref(),
            &[inp_root_nonce],
        ];
        let out_signer = &[&out_seeds[..]];
        let out_accounts = Transfer {
            from: acc_out_token_src,
            to: acc_out_token_dst,
            authority: ctx.accounts.root_data.to_account_info(),
        };
        let cpi_prog2 = ctx.accounts.token_program.clone();
        let out_ctx = CpiContext::new_with_signer(cpi_prog2, out_accounts, out_signer);
        msg!("Atellix: Attempt Outbound Transfer");
        token::transfer(out_ctx, tokens_out)?;

        if fees_net > 0 {
            if sw.fees_inbound {
                let fees_seeds = &[
                    ctx.program_id.as_ref(),
                    &[inp_root_nonce],
                ];
                let fees_signer = &[&fees_seeds[..]];
                let fees_accounts = Transfer {
                    from: acc_inb_token_dst,
                    to: ctx.accounts.fees_account.to_account_info(),
                    authority: ctx.accounts.root_data.to_account_info(),
                };
                let cpi_prog = ctx.accounts.token_program.clone();
                let fees_ctx = CpiContext::new_with_signer(cpi_prog, fees_accounts, fees_signer);
                msg!("Atellix: Attempt Fees Transfer - Inbound Token");
                token::transfer(fees_ctx, fees_net)?;
            } else {
                let fees_seeds = &[
                    ctx.program_id.as_ref(),
                    &[inp_root_nonce],
                ];
                let fees_signer = &[&fees_seeds[..]];
                let fees_accounts = Transfer {
                    from: acc_out_token_src,
                    to: ctx.accounts.fees_account.to_account_info(),
                    authority: ctx.accounts.root_data.to_account_info(),
                };
                let cpi_prog = ctx.accounts.token_program.clone();
                let fees_ctx = CpiContext::new_with_signer(cpi_prog, fees_accounts, fees_signer);
                msg!("Atellix: Attempt Fees Transfer - Outbound Token");
                token::transfer(fees_ctx, fees_net)?;
            }
        }

        let clock = Clock::get()?;
        inb_info.token_tx_count = inb_info.token_tx_count.checked_add(1).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        out_info.token_tx_count = out_info.token_tx_count.checked_add(1).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        inb_info.slot = clock.slot;
        out_info.slot = clock.slot;
        ctx.accounts.swap_data.swap_tx_count = ctx.accounts.swap_data.swap_tx_count.checked_add(1).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        ctx.accounts.swap_data.swap_inb_tokens = ctx.accounts.swap_data.swap_inb_tokens.checked_add(tokens_inb).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        ctx.accounts.swap_data.swap_out_tokens = ctx.accounts.swap_data.swap_out_tokens.checked_add(tokens_out).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        ctx.accounts.swap_data.inb_token_tx = inb_info.token_tx_count;
        ctx.accounts.swap_data.out_token_tx = out_info.token_tx_count;
        ctx.accounts.swap_data.slot = clock.slot;

        emit!(SwapEvent {
            event_hash: 144834217477609949185867766428666600068, // "solana/program/atx-swap-contract/swap" (MurmurHash3 128-bit unsigned)
            slot: clock.slot,
            swap_data: ctx.accounts.swap_data.key(),
            user: ctx.accounts.swap_user.key(),
            inb_mint: inb_info.mint,
            inb_tokens: tokens_inb,
            inb_token_src: ctx.accounts.inb_token_src.key(),
            out_mint: out_info.mint,
            out_tokens: tokens_out,
            out_token_dst: ctx.accounts.out_token_dst.key(),
            fees_mint: if (ctx.accounts.swap_data.fees_inbound) { inb_info.mint } else { out_info.mint },
            fees_amount: fees_net,
            fees_token: ctx.accounts.swap_data.fees_token,
            use_oracle: oracle_log_inuse,
            oracle: oracle_log_key,
            oracle_val: oracle_log_val,
            swap_inb_tokens: ctx.accounts.swap_data.swap_inb_tokens,
            swap_out_tokens: ctx.accounts.swap_data.swap_out_tokens,
            swap_tx: ctx.accounts.swap_data.swap_tx_count,
            inb_token_tx: ctx.accounts.inb_info.token_tx_count,
            out_token_tx: ctx.accounts.out_info.token_tx_count,
        });

        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub root_data: AccountInfo<'info>,
    #[account(mut)]
    pub auth_data: AccountInfo<'info>,
    //pub net_auth: AccountInfo<'info>, // Merchant validator net authority program
    pub program: AccountInfo<'info>,
    pub program_data: AccountInfo<'info>,
    #[account(signer)]
    pub program_admin: AccountInfo<'info>,
    #[account(address = system_program::ID)]
    pub system_program: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct UpdateRBAC<'info> {
    pub root_data: ProgramAccount<'info, RootData>,
    #[account(mut)]
    pub auth_data: AccountInfo<'info>,
    pub program: AccountInfo<'info>,
    pub program_data: AccountInfo<'info>,
    #[account(signer)]
    pub program_admin: AccountInfo<'info>,
    pub rbac_user: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct ApproveToken<'info> {
    pub root_data: ProgramAccount<'info, RootData>,
    pub auth_data: AccountInfo<'info>,
    #[account(mut, signer)]
    pub swap_admin: AccountInfo<'info>,
    #[account(mut)]
    pub swap_token: AccountInfo<'info>,
    pub token_mint: AccountInfo<'info>,
    #[account(mut)]
    pub token_info: AccountInfo<'info>,
    #[account(address = token::ID)]
    pub token_program: AccountInfo<'info>,
    pub asc_program: AccountInfo<'info>,
    #[account(address = system_program::ID)]
    pub system_program: AccountInfo<'info>,
    #[account(address = sysvar::rent::ID)]
    pub system_rent: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct CreateSwap<'info> {
    pub root_data: ProgramAccount<'info, RootData>,
    pub auth_data: AccountInfo<'info>,
    #[account(signer)]
    pub swap_admin: AccountInfo<'info>,
    #[account(mut)]
    pub swap_data: AccountInfo<'info>,
    pub inb_info: ProgramAccount<'info, TokenInfo>,
    pub out_info: ProgramAccount<'info, TokenInfo>,
    pub fees_account: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct MintDeposit<'info> {
    pub root_data: ProgramAccount<'info, RootData>,
    pub auth_data: AccountInfo<'info>,
    #[account(signer)]
    pub swap_admin: AccountInfo<'info>,
    #[account(mut)]
    pub swap_token: AccountInfo<'info>,
    #[account(signer)]
    pub token_admin: AccountInfo<'info>,
    #[account(mut)]
    pub token_mint: AccountInfo<'info>,
    #[account(mut)]
    pub token_info: ProgramAccount<'info, TokenInfo>,
    #[account(address = token::ID)]
    pub token_program: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct TransferDeposit<'info> {
    pub root_data: ProgramAccount<'info, RootData>,
    pub auth_data: AccountInfo<'info>,
    #[account(signer)]
    pub swap_admin: AccountInfo<'info>,
    #[account(mut)]
    pub swap_token: AccountInfo<'info>,
    #[account(signer)]
    pub token_admin: AccountInfo<'info>,
    #[account(mut)]
    pub token_mint: AccountInfo<'info>,
    #[account(mut)]
    pub token_info: ProgramAccount<'info, TokenInfo>,
    #[account(mut)]
    pub token_src: AccountInfo<'info>,
    #[account(address = token::ID)]
    pub token_program: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    pub root_data: ProgramAccount<'info, RootData>,
    pub auth_data: AccountInfo<'info>,
    #[account(signer)]
    pub swap_admin: AccountInfo<'info>,
    #[account(mut)]
    pub swap_token: AccountInfo<'info>,
    #[account(signer)]
    pub token_admin: AccountInfo<'info>,
    #[account(mut)]
    pub token_mint: AccountInfo<'info>,
    #[account(mut)]
    pub token_info: ProgramAccount<'info, TokenInfo>,
    #[account(mut)]
    pub token_dst: AccountInfo<'info>,
    #[account(address = token::ID)]
    pub token_program: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct Swap<'info> {
    pub root_data: ProgramAccount<'info, RootData>,
    pub auth_data: AccountInfo<'info>,
    #[account(signer)]
    pub swap_user: AccountInfo<'info>,
    #[account(mut)]
    pub swap_data: ProgramAccount<'info, SwapData>,
    #[account(mut)]
    pub inb_info: ProgramAccount<'info, TokenInfo>,
    #[account(mut)]
    pub inb_token_src: AccountInfo<'info>,
    #[account(mut)]
    pub inb_token_dst: AccountInfo<'info>,
    #[account(mut)]
    pub out_info: ProgramAccount<'info, TokenInfo>,
    #[account(mut)]
    pub out_token_src: AccountInfo<'info>,
    #[account(mut)]
    pub out_token_dst: AccountInfo<'info>,
    #[account(mut)]
    pub fees_token: AccountInfo<'info>,
    #[account(address = token::ID)]
    pub token_program: AccountInfo<'info>,
}

#[account]
pub struct SwapData {
    pub active: bool,                   // Active flag
    pub slot: u64,                      // Last slot updated
    pub merchant_only: bool,            // Merchant-only flag
    pub oracle_data: Pubkey,            // Oracle data address or Pubkey::default() for none
    pub oracle_type: u8,                // Oracle data type
    pub oracle_rates: bool,             // Uses oracle data for swap rates
    pub oracle_inverse: bool,           // Inverse the oracle rate
    pub oracle_verify: bool,            // Uses oracle data to check for a valid range
    pub oracle_verify_min: u64,         // Valid range minimum (times 10**6, or 6 decimals)
    pub oracle_verify_max: u64,         // Valid range maximum (times 10**6, or 6 decimals)
    pub rate_swap: u64,                 // Swap rate
    pub rate_base: u64,                 // Base rate
    pub inb_token_info: Pubkey,         // Token info for inbound tokens
    pub inb_token_tx: u64,              // Last transaction id for token
    pub out_token_info: Pubkey,         // Token info for outbound tokens
    pub out_token_tx: u64,              // Last transaction id for token
    pub fees_inbound: bool,             // Use inbound (or alternatively outbound) token for fees
    pub fees_token: Pubkey,             // Fees account
    pub fees_bps: u32,                  // Swap fees in basis points
    pub fees_total: u64,                // All swap fees charged
    pub swap_tx_count: u64,             // Transaction ID sequence for swap
    pub swap_inb_tokens: u64,           // Total tokens inbound, net of deposits/withdrawals
    pub swap_out_tokens: u64,           // Total tokens outbound, net of deposits/withdrawals
}

#[account]
pub struct TokenInfo {
    pub mint: Pubkey,
    pub decimals: u8,
    pub amount: u64,
    pub token_tx_count: u64,
    pub slot: u64,
}

#[account]
pub struct RootData {
    pub root_authority: Pubkey,
}

impl RootData {
    pub fn root_authority(&self) -> Pubkey {
        self.root_authority
    }

    pub fn set_root_authority(&mut self, new_authority: Pubkey) {
        self.root_authority = new_authority
    }
}

impl Default for RootData {
    fn default() -> Self {
        Self {
            root_authority: Pubkey::default(),
        }
    }
}

#[event]
pub struct SwapEvent {
    pub event_hash: u128,
    pub slot: u64,
    pub swap_data: Pubkey,
    pub user: Pubkey,
    pub inb_mint: Pubkey,
    pub inb_tokens: u64,
    pub inb_token_src: Pubkey,
    pub out_mint: Pubkey,
    pub out_tokens: u64,
    pub out_token_dst: Pubkey,
    pub fees_mint: Pubkey,
    pub fees_amount: u64,
    pub fees_token: Pubkey,
    pub use_oracle: bool,
    pub oracle: Pubkey,
    pub oracle_val: u128,
    pub swap_out_tokens: u64,
    pub swap_inb_tokens: u64,
    pub swap_tx: u64,
    pub inb_token_tx: u64,
    pub out_token_tx: u64,
}

#[event]
pub struct TransferEvent {
    pub event_hash: u128,
    pub slot: u64,
    pub user: Pubkey,
    pub token_info: Pubkey,
    pub token_acct: Pubkey, // The source or destination associated token (or default for mint)
    pub deposit: bool, // or, withdraw
    pub transfer: bool, // or, mint
    pub amount: u64,
    pub new_total: u64,
    pub token_tx: u64,
}

#[error]
pub enum ErrorCode {
    #[msg("Access denied")]
    AccessDenied,
    #[msg("Invalid parameters")]
    InvalidParameters,
    #[msg("Invalid account")]
    InvalidAccount,
    #[msg("Invalid derived account")]
    InvalidDerivedAccount,
    #[msg("Internal error")]
    InternalError,
    #[msg("Overflow")]
    Overflow,
}

