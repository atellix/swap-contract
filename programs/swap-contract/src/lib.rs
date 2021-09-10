use std::{ io::Cursor, string::String, str::FromStr };
use bytemuck::{ Pod, Zeroable };
use byte_slice_cast::*;
use num_enum::TryFromPrimitive;
use switchboard_program;
use switchboard_program::{ FastRoundResultAccountData };
use anchor_lang::prelude::*;
use anchor_spl::token::{ self, MintTo, Transfer };
use solana_program::{
    sysvar, system_instruction, system_program,
    program::{ invoke, invoke_signed },
    account_info::AccountInfo,
    instruction::{ AccountMeta, Instruction }
};

extern crate slab_alloc;
use slab_alloc::{ SlabPageAlloc, CritMapHeader, CritMap, AnyNode, LeafNode, SlabVec };

extern crate decode_account;
use decode_account::parse_bpf_loader::{ parse_bpf_upgradeable_loader, BpfUpgradeableLoaderAccountType };

pub const MAX_RBAC: u32 = 1024;

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
}

#[derive(Copy, Clone)]
#[repr(packed)]
pub struct UserRBAC {
    pub active: bool,
    pub user_key: Pubkey,
    pub role: Role,
}
unsafe impl Zeroable for UserRBAC {}
unsafe impl Pod for UserRBAC {}

impl UserRBAC {
    pub fn active(&self) -> bool {
        self.active
    }

    pub fn set_active(&mut self, new_status: bool) {
        self.active = new_status
    }

    pub fn user_key(&self) -> Pubkey {
        self.user_key
    }

    pub fn role(&self) -> Role {
        self.role
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
fn map_get(pt: &mut SlabPageAlloc, data_type: DT, key: u128) -> Option<u32> {
    let cm = CritMap { slab: pt, type_id: map_datatype(data_type), capacity: map_len(data_type) };
    let rf = cm.get_key(key);
    match rf {
        None => None,
        Some(res) => Some(res.data()),
    }
}

#[inline]
fn map_set(pt: &mut SlabPageAlloc, data_type: DT, key: u128, data: u32) {
    let mut cm = CritMap { slab: pt, type_id: map_datatype(data_type), capacity: map_len(data_type) };
    let node = LeafNode::new(key, data);
    cm.insert_leaf(&node).expect("Failed to insert leaf");
}

#[inline]
fn next_index(pt: &mut SlabPageAlloc, data_type: DT) -> u32 {
    let svec = pt.header_mut::<SlabVec>(index_datatype(data_type));
    svec.next_index()
}

fn has_role(acc_auth: &AccountInfo, role: Role, key: &Pubkey) -> ProgramResult {
    let auth_data: &mut [u8] = &mut acc_auth.try_borrow_mut_data()?;
    let rd = SlabPageAlloc::new(auth_data);
    let authhash: u128 = CritMap::bytes_hash([[role as u32].as_byte_slice(), key.as_ref()].concat().as_slice());
    let authrec = map_get(rd, DT::UserRBAC, authhash);
    if ! authrec.is_some() {
        //msg!("Role not found");
        return Err(ErrorCode::AccessDenied.into());
    }
    let urec = rd.index::<UserRBAC>(DT::UserRBAC as u16, authrec.unwrap() as usize);
    if urec.user_key != *key {
        msg!("User key does not match signer");
        return Err(ErrorCode::AccessDenied.into());
    }
    if ! urec.active() {
        msg!("Role revoked");
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
            // Check if record is active
            let rec_idx = authrec.unwrap() as usize;
            let urec = rd.index_mut::<UserRBAC>(DT::UserRBAC as u16, rec_idx);
            if urec.active() {
                msg!("Role already active");
            } else {
                urec.set_active(true);
                msg!("Role resumed");
            }
        } else {
            // Add new record
            let rbac_idx = next_index(rd, DT::UserRBAC);
            let ur = UserRBAC {
                active: true,
                user_key: *acc_rbac.key,
                role: role,
            };
            *rd.index_mut(DT::UserRBAC as u16, rbac_idx as usize) = ur;
            map_set(rd, DT::UserRBAC, authhash, rbac_idx);
            msg!("Role granted");
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
            // Check if record is active
            let rec_idx = authrec.unwrap() as usize;
            let urec = rd.index_mut::<UserRBAC>(DT::UserRBAC as u16, rec_idx);
            if urec.active() {
                urec.set_active(false);
                msg!("Role revoked");
            } else {
                msg!("Role already revoked");
            }
        } else {
            msg!("Role not found");
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

        let admin_role = has_role(&acc_auth, Role::SwapDeposit, acc_admn.key);
        if admin_role.is_err() {
            msg!("No swap deposit role");
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

        let ra = TokenInfo {
            mint: *acc_mint.key,
            decimals: inp_decimals,
            amount: 0,
        };
        let mut tk_data = acc_info.try_borrow_mut_data()?;
        let tk_dst: &mut [u8] = &mut tk_data;
        let mut tk_crs = Cursor::new(tk_dst);
        ra.try_serialize(&mut tk_crs)?;

        Ok(())
    }

    pub fn create_swap(ctx: Context<CreateSwap>,
        inp_root_nonce: u8,         // RootData nonce
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

        let sw = SwapData {
            active: true,
            oracle_data: Pubkey::default(),
            oracle_rates: false,
            oracle_verify: false,
            oracle_verify_min: 0,
            oracle_verify_max: 0,
            symmetrical_swap: true,
            inb_token_info: *acc_inb.key,
            out_token_info: *acc_out.key,
            fees_inbound: true,
            fees_account: Pubkey::default(),
            fees_bps: 0,
        };
        let mut sw_data = acc_swap.try_borrow_mut_data()?;
        let sw_dst: &mut [u8] = &mut sw_data;
        let mut sw_crs = Cursor::new(sw_dst);
        sw.try_serialize(&mut sw_crs)?;

        Ok(())
    }

    pub fn deposit(ctx: Context<Deposit>,
        inp_root_nonce: u8,         // RootData nonce
        inp_tinf_nonce: u8,         // Token Info nonce
        inp_tokn_nonce: u8,         // Associated token nonce
        inp_mint: bool,             // Mint (true) or Transfer (false)
        inp_amount: u64,            // Amount to mint or transfer
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

        if inp_mint {
            let cpi_accounts = MintTo {
                mint: acc_mint.clone(),
                to: acc_tokn.clone(),
                authority: acc_tadm.clone(),
            };
            let cpi_program = acc_prog.clone();
            let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);
            token::mint_to(cpi_ctx, inp_amount)?;
        } else {
            msg!("under construction");
        }

        ctx.accounts.token_info.amount = ctx.accounts.token_info.amount.checked_add(inp_amount).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        msg!("Atellix: New token amount: {}", ctx.accounts.token_info.amount.to_string());

        Ok(())
    }

/*    pub fn withdraw(ctx: Context<Initialize>) -> ProgramResult {
        Ok(())
    } */

    pub fn swap(ctx: Context<Swap>,
        inp_root_nonce: u8,
        inp_inb_nonce: u8,         // Associated token nonce for inb_token_dst
        inp_out_nonce: u8,         // Associated token nonce for out_token_src
        inp_out_tokens: u64,       // Number of tokens to receive
    ) -> ProgramResult {
        let acc_root = &ctx.accounts.root_data.to_account_info();
        let acc_auth = &ctx.accounts.auth_data.to_account_info();

        // Verify program data
        let acc_root_expected = Pubkey::create_program_address(&[ctx.program_id.as_ref(), &[inp_root_nonce]], ctx.program_id)
            .map_err(|_| ErrorCode::InvalidDerivedAccount)?;
        verify_matching_accounts(acc_root.key, &acc_root_expected, Some(String::from("Invalid root data")))?;
        verify_matching_accounts(acc_auth.key, &ctx.accounts.root_data.root_authority, Some(String::from("Invalid root authority")))?;

        // TODO: verify merchants with net authority if needed

        let acc_inb = &ctx.accounts.inb_info.to_account_info();
        let acc_inb_mint = &ctx.accounts.inb_mint.to_account_info();
        let acc_out = &ctx.accounts.out_info.to_account_info();
        let acc_out_mint = &ctx.accounts.out_mint.to_account_info();
        let sw = &ctx.accounts.swap_data;
        verify_matching_accounts(&sw.inb_token_info, acc_inb.key, Some(String::from("Invalid inbound token info")))?;
        verify_matching_accounts(&sw.out_token_info, acc_out.key, Some(String::from("Invalid outbound token info")))?;
        let inb_info = &mut ctx.accounts.inb_info;
        let out_info = &mut ctx.accounts.out_info;
        verify_matching_accounts(&inb_info.mint, acc_inb_mint.key, Some(String::from("Invalid inbound mint")))?;
        verify_matching_accounts(&out_info.mint, acc_out_mint.key, Some(String::from("Invalid outbound mint")))?;

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
                &acc_inb_mint.key.to_bytes(),
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
                &acc_out_mint.key.to_bytes(),
                &[inp_out_nonce]
            ],
            &asc_token
        ).map_err(|_| ErrorCode::InvalidDerivedAccount)?;
        if derived_key_out != *acc_out_token_src.key {
            msg!("Invalid outbound token source account");
            return Err(ErrorCode::InvalidDerivedAccount.into());
        }

        msg!("Atellix: Tokens verified ready to swap");
        let mut tokens_inb: u64 = inp_out_tokens;
        let mut tokens_out: u64 = inp_out_tokens;
        //let mut tokens_fee: u64 = 0;

        inb_info.amount = inb_info.amount.checked_add(tokens_inb).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        out_info.amount = out_info.amount.checked_sub(tokens_out).ok_or(ProgramError::from(ErrorCode::Overflow))?;

        msg!("Atellix: New Inbound Amount: {}", inb_info.amount.to_string());
        msg!("Atellix: New Outbound Amount: {}", out_info.amount.to_string());

        let in_accounts = Transfer {
            from: acc_inb_token_src,
            to: acc_inb_token_dst,
            authority: ctx.accounts.swap_user.to_account_info(),
        };
        let cpi_prog1 = ctx.accounts.token_program.clone();
        let in_ctx = CpiContext::new(cpi_prog1, in_accounts);
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
        token::transfer(out_ctx, tokens_out)?;

        Ok(())
    }

    pub fn oracle_result(ctx: Context<OracleResult>) -> ProgramResult {
        let acc_data = &ctx.accounts.oracle_data.to_account_info();
        let feed_data = FastRoundResultAccountData::deserialize(&acc_data.try_borrow_data()?).unwrap();
        let round_data = feed_data.result;
        msg!("Data: {}", round_data.result.to_string());
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
pub struct Deposit<'info> {
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
pub struct Swap<'info> {
    pub root_data: ProgramAccount<'info, RootData>,
    pub auth_data: AccountInfo<'info>,
    #[account(signer)]
    pub swap_user: AccountInfo<'info>,
    pub swap_data: ProgramAccount<'info, SwapData>,
    #[account(mut)]
    pub inb_info: ProgramAccount<'info, TokenInfo>,
    #[account(mut)]
    pub inb_token_src: AccountInfo<'info>,
    #[account(mut)]
    pub inb_token_dst: AccountInfo<'info>,
    pub inb_mint: AccountInfo<'info>,
    #[account(mut)]
    pub out_info: ProgramAccount<'info, TokenInfo>,
    #[account(mut)]
    pub out_token_src: AccountInfo<'info>,
    #[account(mut)]
    pub out_token_dst: AccountInfo<'info>,
    pub out_mint: AccountInfo<'info>,
    #[account(address = token::ID)]
    pub token_program: AccountInfo<'info>,
    // Fees
    // Oracle
    // Merchant approval
}

#[derive(Accounts)]
pub struct OracleResult<'info> {
    pub oracle_data: AccountInfo<'info>,
}

#[account]
pub struct SwapData {
    pub active: bool,                   // Active flag
    //pub merchant_only: bool,            // Merchant-only flag
    pub oracle_data: Pubkey,            // Oracle data address or Pubkey::default() for none
    pub oracle_rates: bool,             // Uses oracle data for swap rates
    pub oracle_verify: bool,            // Uses oracle data to check for a valid range
    pub oracle_verify_min: u64,         // Valid range minimum (times 10**6, or 6 decimals)
    pub oracle_verify_max: u64,         // Valid range maximum (times 10**6, or 6 decimals)
    pub symmetrical_swap: bool,         // 1:1 swap for stablecoins
    pub inb_token_info: Pubkey,         // Token info for inbound tokens
    pub out_token_info: Pubkey,         // Token info for outbound tokens
    pub fees_inbound: bool,             // Use inbound (or alternatively outbound) token for fees
    pub fees_account: Pubkey,           // Fees account
    pub fees_bps: u32,                  // Swap fees in basis points
}

#[account]
pub struct TokenInfo {
    pub mint: Pubkey,
    pub decimals: u8,
    pub amount: u64,
}

#[account]
pub struct RootData {
    pub root_authority: Pubkey,
    //pub net_authority: Pubkey, // Used to verify merchant approvals
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
    #[msg("Overflow")]
    Overflow,
}

