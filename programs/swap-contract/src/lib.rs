use std::{ io::Cursor };
use solana_program::{
    program::{ invoke_signed },
    account_info::AccountInfo,
    system_instruction
};
use bytemuck::{ Pod, Zeroable };
use byte_slice_cast::*;
use num_enum::TryFromPrimitive;
use anchor_lang::prelude::*;
use switchboard_program;
use switchboard_program::{ FastRoundResultAccountData };

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
        {
            let acc_prog = &ctx.accounts.program.to_account_info();
            let acc_pdat = &ctx.accounts.program_data.to_account_info();
            let acc_user = &ctx.accounts.program_admin.to_account_info();
            verify_program_owner(ctx.program_id, &acc_prog, &acc_pdat, &acc_user)?;
        }
        let av = ctx.remaining_accounts;
        let funder_info = av.get(0).unwrap();
        let data_account_info = av.get(1).unwrap();
        let system_program_info = av.get(2).unwrap();
        let (data_account_address, bump_seed) = Pubkey::find_program_address(
            &[ctx.program_id.as_ref()],
            ctx.program_id,
        );
        if data_account_address != *data_account_info.key {
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
                funder_info.key,
                data_account_info.key,
                inp_root_rent,
                inp_root_size,
                ctx.program_id
            ),
            &[
                funder_info.clone(),
                data_account_info.clone(),
                system_program_info.clone(),
            ],
            &[account_signer_seeds],
        )?;

        let acc_root = &ctx.accounts.root_data.to_account_info();
        let acc_auth = &ctx.accounts.auth_data.to_account_info();
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

    pub fn deposit(ctx: Context<Deposit>,
        inp_root_nonce: u8,         // RootData nonce
        //inp_mint: bool,             // Mint (true) or transfer (false)
    ) -> ProgramResult {
        let acc_admn = &ctx.accounts.swap_admin.to_account_info(); // Swap admin
        let acc_root = &ctx.accounts.root_data.to_account_info();
        let acc_auth = &ctx.accounts.auth_data.to_account_info();

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

        msg!("Atellix: Deposit ready");

        Ok(())
    }

/*    pub fn withdraw(ctx: Context<Initialize>) -> ProgramResult {
        Ok(())
    }

    pub fn swap(ctx: Context<Initialize>) -> ProgramResult {
        Ok(())
    } */

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
    pub root_data: AccountInfo<'info>,
    #[account(mut)]
    pub auth_data: AccountInfo<'info>,
    pub program: AccountInfo<'info>,
    pub program_data: AccountInfo<'info>,
    #[account(signer)]
    pub program_admin: AccountInfo<'info>,
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
pub struct Deposit<'info> {
    pub root_data: ProgramAccount<'info, RootData>,
    pub auth_data: AccountInfo<'info>,
    #[account(signer)]
    pub swap_admin: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct OracleResult<'info> {
    pub oracle_data: AccountInfo<'info>,
}

#[account]
pub struct SwapData {
    pub active: bool,                   // Active flag
    //pub merchant_only: bool,            // Merchant-only flag
    pub oracle_rates: bool,             // Uses oracle data for swap rates
    pub oracle_verify: bool,            // Uses oracle data to check for a valid range
    pub oracle_verify_min: u64,         // Valid range minimum (times 10**6, or 6 decimals)
    pub oracle_verify_max: u64,         // Valid range maximum (times 10**6, or 6 decimals)
    pub symmetrical_swap: bool,         // 1:1 swap for stablecoins
    pub inb_token_mint: Pubkey,         // Token mint for inbound tokens
    pub inb_token_decimals: u8,         // Inbound token decimals
    pub out_token_mint: Pubkey,         // Token mint for outbound tokens
    pub out_token_decimals: u8,         // Outbound token decimals
    pub out_token_balance: u64,         // Number of tokens available to trade
    pub fees_inbound: bool,             // Use inbound (or alternatively outbound) token for fees
    pub fees_account: Pubkey,           // Fees account (always the inbound token)
    pub fees_bps: u32,                  // Swap fees in basis points
}

/*#[account]
pub struct TokenData {
}*/

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

