use std::{ io::Cursor, string::String, str::FromStr, result::Result as FnResult, convert::TryFrom };
use bytemuck::{ Pod, Zeroable };
use byte_slice_cast::*;
use num_enum::{ TryFromPrimitive, IntoPrimitive };
use arrayref::array_ref;
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

use net_authority::{ cpi::accounts::RecordRevenue, MerchantApproval };

extern crate slab_alloc;
use slab_alloc::{ SlabPageAlloc, CritMapHeader, CritMap, AnyNode, LeafNode, SlabVec, SlabTreeError };

extern crate decode_account;
use decode_account::parse_bpf_loader::{ parse_bpf_upgradeable_loader, BpfUpgradeableLoaderAccountType };

declare_id!("SWAPHoyLAfhNa77PnnnNWWWDLPHuSJueuqveVL52sNS");

pub const VERSION_MAJOR: u32 = 1;
pub const VERSION_MINOR: u32 = 0;
pub const VERSION_PATCH: u32 = 0;

pub const MAX_RBAC: u32 = 128;
pub const SPL_TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
pub const ASC_TOKEN: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";

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
    NetworkAdmin,           // 0 - Can manage RBAC for other users
    NetworkAuth,            // 1 - Valid network authority for merchant approvals
    SwapAdmin,              // 2 - Can create swap exchanges and set parameters, rates, etc...
    SwapDeposit,            // 3 - Can deposit to swap contracts
    SwapWithdraw,           // 4 - Can withdraw from swap contracts
    SwapUpdate,             // 5 - Can update swap parameters
    SwapAbort,              // 6 - Can deactivate swaps
    SwapPermit,             // 7 - Can receive withdrawn tokens
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
        msg!("Expected: {}", program_owner);
        msg!("Received: {}", acc_user.key.to_string());
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

fn verify_program_data(bump_seed: u8, root_key: &Pubkey, program: &Pubkey) -> ProgramResult {
    let acc_root_expected = Pubkey::create_program_address(&[program.as_ref(), &[bump_seed]], program)
        .map_err(|_| ErrorCode::InvalidDerivedAccount)?;
    verify_matching_accounts(root_key, &acc_root_expected, Some(String::from("Invalid root data")))?;
    Ok(())
}

fn calculate_swap(sw: &SwapData, is_buy: bool, input_val: u128, swap_rate: u128, base_rate: u128, extra_decimals: u128) -> FnResult<u128, ProgramError> {
    let nmr_1: u128;
    if sw.fees_bps > 0 {
        let mut fee_part: u128 = input_val.checked_mul(sw.fees_bps as u128).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        fee_part = fee_part.checked_div(10000).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        if is_buy {
            nmr_1 = input_val.checked_add(fee_part).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        } else {
            nmr_1 = input_val.checked_sub(fee_part).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        }
    } else {
        nmr_1 = input_val;
    }
    let nmr_2: u128;
    let mut dnm_1: u128;
    if is_buy {
        nmr_2 = swap_rate;
        dnm_1 = base_rate;
    } else {
        nmr_2 = base_rate;
        dnm_1 = swap_rate;
    }
    let mut nmr_3: u128 = nmr_1.checked_mul(nmr_2).ok_or(ProgramError::from(ErrorCode::Overflow))?;
    if sw.oracle_rates { 
        if sw.oracle_inverse {
            if is_buy {
                dnm_1 = dnm_1.checked_mul(extra_decimals).ok_or(ProgramError::from(ErrorCode::Overflow))?;
            } else {
                nmr_3 = nmr_3.checked_mul(extra_decimals).ok_or(ProgramError::from(ErrorCode::Overflow))?;
            }
        } else {
            if is_buy {
                nmr_3 = nmr_3.checked_mul(extra_decimals).ok_or(ProgramError::from(ErrorCode::Overflow))?;
            } else {
                dnm_1 = dnm_1.checked_mul(extra_decimals).ok_or(ProgramError::from(ErrorCode::Overflow))?;
            }
        }
    }
    let result: u128 = nmr_3.checked_div(dnm_1).ok_or(ProgramError::from(ErrorCode::Overflow))?;
    Ok(result)
}

fn calculate_fee(sw: &SwapData, is_buy: bool, input_val: u128, swap_rate: u128, base_rate: u128, extra_decimals: u128) -> FnResult<u64, ProgramError> {
    let mut top_pow: bool = false; // Use extra_decimals for actual value
    let mut btm_pow: bool = false;
    if sw.fees_bps > 0 {
        let mut fee_1 = input_val.checked_mul(sw.fees_bps as u128).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        fee_1 = fee_1.checked_div(10000).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        if sw.fees_inbound { // Fees on inbound token
            if sw.oracle_rates && is_buy {
                if sw.oracle_inverse {
                    btm_pow = true;
                } else {
                    top_pow = true;
                }
            }
            if is_buy {
                fee_1 = fee_1.checked_mul(swap_rate).ok_or(ProgramError::from(ErrorCode::Overflow))?;
                if top_pow {
                    fee_1 = fee_1.checked_mul(extra_decimals).ok_or(ProgramError::from(ErrorCode::Overflow))?;
                }
                let mut fee_2: u128 = base_rate;
                if btm_pow {
                    fee_2 = fee_2.checked_mul(extra_decimals).ok_or(ProgramError::from(ErrorCode::Overflow))?;
                }
                fee_1 = fee_1.checked_div(fee_2).ok_or(ProgramError::from(ErrorCode::Overflow))?;
            }
        } else { // Fees on outbound token
            if sw.oracle_rates && ! is_buy {
                if sw.oracle_inverse {
                    top_pow = true;
                } else {
                    btm_pow = true;
                }
            }
            if ! is_buy {
                fee_1 = fee_1.checked_mul(base_rate).ok_or(ProgramError::from(ErrorCode::Overflow))?;
                if top_pow {
                    fee_1 = fee_1.checked_mul(extra_decimals).ok_or(ProgramError::from(ErrorCode::Overflow))?;
                }
                let mut fee_2: u128 = swap_rate;
                if btm_pow {
                    fee_2 = fee_2.checked_mul(extra_decimals).ok_or(ProgramError::from(ErrorCode::Overflow))?;
                }
                fee_1 = fee_1.checked_div(fee_2).ok_or(ProgramError::from(ErrorCode::Overflow))?;
            }
        }
        let fee: u64 = u64::try_from(fee_1).map_err(|_| ErrorCode::Overflow)?;
        return Ok(fee)
    }
    Ok(0)
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
        let (root_address, bump_seed) = Pubkey::find_program_address(
            &[ctx.program_id.as_ref()],
            ctx.program_id,
        );
        verify_matching_accounts(&root_address, &ctx.accounts.root_data.to_account_info().key,
            Some(String::from("Invalid root data account"))
        )?;

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
            active: true,
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

    pub fn store_metadata(ctx: Context<UpdateMetadata>,
        inp_create: bool,
        inp_info_size: u64,
        inp_info_rent: u64,
        inp_program_name: String,
        inp_developer_name: String,
        inp_developer_url: String,
        inp_source_url: String,
        inp_verify_url: String,
    ) -> ProgramResult {
        let acc_prog = &ctx.accounts.program.to_account_info();
        let acc_pdat = &ctx.accounts.program_data.to_account_info();
        let acc_user = &ctx.accounts.program_admin.to_account_info();
        let acc_info = &ctx.accounts.program_info.to_account_info();
        let acc_sys = &ctx.accounts.system_program.to_account_info();
        verify_program_owner(ctx.program_id, &acc_prog, &acc_pdat, &acc_user)?;
        if inp_create {
            let (info_address, bump_seed) = Pubkey::find_program_address(
                &[ctx.program_id.as_ref(), String::from("metadata").as_ref()],
                ctx.program_id,
            );
            verify_matching_accounts(&info_address, &acc_info.key,
                Some(String::from("Invalid program_info account"))
            )?;
            let mdstr = String::from("metadata");
            let account_signer_seeds: &[&[_]] = &[
                ctx.program_id.as_ref(),
                mdstr.as_ref(),
                &[bump_seed],
            ];
            invoke_signed(
                &system_instruction::create_account(
                    acc_user.key,
                    acc_info.key,
                    inp_info_rent,
                    inp_info_size,
                    ctx.program_id
                ),
                &[
                    acc_user.clone(),
                    acc_info.clone(),
                    acc_sys.clone(),
                ],
                &[account_signer_seeds],
            )?;
        }
        let md = ProgramMetadata {
            semvar_major: VERSION_MAJOR,
            semvar_minor: VERSION_MINOR,
            semvar_patch: VERSION_PATCH,
            program: *ctx.accounts.program.to_account_info().key,
            program_name: inp_program_name,
            developer_name: inp_developer_name,
            developer_url: inp_developer_url,
            source_url: inp_source_url,
            verify_url: inp_verify_url,
        };
        let acc_info = &ctx.accounts.program_info.to_account_info();
        let mut info_data = acc_info.try_borrow_mut_data()?;
        let info_dst: &mut [u8] = &mut info_data;
        let mut info_crs = Cursor::new(info_dst);
        md.try_serialize(&mut info_crs)?;
        msg!("Program: {}", ctx.accounts.program.key.to_string());
        msg!("Program Name: {}", md.program_name.as_str());
        msg!("Version: {}.{}.{}", VERSION_MAJOR.to_string(), VERSION_MINOR.to_string(), VERSION_PATCH.to_string());
        msg!("Developer Name: {}", md.developer_name.as_str());
        msg!("Developer URL: {}", md.developer_url.as_str());
        msg!("Source URL: {}", md.source_url.as_str());
        msg!("Verify URL: {}", md.verify_url.as_str());
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
        let spl_token: Pubkey = Pubkey::from_str(SPL_TOKEN).unwrap();
        let asc_token: Pubkey = Pubkey::from_str(ASC_TOKEN).unwrap();
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
        inp_oracle_max: bool,       // Use oracle if greater
        inp_oracle_inverse: bool,   // Inverse the oracle for "Buy" orders
        inp_oracle_verify: bool,    // Use oracle to verify price range (to check peg stability on stablecoins)
        inp_oracle_type: u8,        // Use oracle type
        inp_verify_min: u64,        // Minimum of price range (0 for unused)
        inp_verify_max: u64,        // Maximum of price range (0 for unused)
        inp_swap_rate: u64,         // Swap rate
        inp_base_rate: u64,         // Base rate
        inp_fees_inbound: bool,     // Take fees from inbound token (alternatively use the outbound token)
        inp_fees_bps: u32,          // Fees basis points
        inp_merchant_only: bool,    // Merchant-only swap
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
            locked: false,
            slot: clock.slot,
            merchant_only: inp_merchant_only,
            oracle_data: oracle,
            oracle_type: inp_oracle_type,
            oracle_rates: inp_oracle_rates,
            oracle_max: inp_oracle_max,
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
            fees_total: 0,
            swap_tx_count: 0,
            swap_inb_tokens: 0,
            swap_out_tokens: 0,
        };
        let mut sw_data = acc_swap.try_borrow_mut_data()?;
        let disc_bytes = array_ref![sw_data, 0, 8];
        if disc_bytes != &[0; 8] {
            msg!("Account already initialized");
            return Err(ErrorCode::InvalidAccount.into());
        }
        let sw_dst: &mut [u8] = &mut sw_data;
        let mut sw_crs = Cursor::new(sw_dst);
        sw.try_serialize(&mut sw_crs)?;

        Ok(())
    }

    pub fn update_swap(ctx: Context<UpdateSwap>,
        inp_root_nonce: u8,         // RootData nonce
        inp_locked: bool,           // Lock / unlock
        inp_oracle_verify: bool,    // Use oracle to verify price range (to check peg stability on stablecoins)
        inp_verify_min: u64,        // Minimum of price range (0 for unused)
        inp_verify_max: u64,        // Maximum of price range (0 for unused)
        inp_swap_rate: u64,         // Swap rate
        inp_base_rate: u64,         // Base rate
        inp_fees_bps: u32,          // Fees basis points
    ) -> ProgramResult {
        let acc_admn = &ctx.accounts.swap_admin.to_account_info(); // SwapUpdate role
        let acc_root = &ctx.accounts.root_data.to_account_info();
        let acc_auth = &ctx.accounts.auth_data.to_account_info();

        // Verify program data
        let acc_root_expected = Pubkey::create_program_address(&[ctx.program_id.as_ref(), &[inp_root_nonce]], ctx.program_id)
            .map_err(|_| ErrorCode::InvalidDerivedAccount)?;
        verify_matching_accounts(acc_root.key, &acc_root_expected, Some(String::from("Invalid root data")))?;
        verify_matching_accounts(acc_auth.key, &ctx.accounts.root_data.root_authority, Some(String::from("Invalid root authority")))?;

        let sw = &mut ctx.accounts.swap_data;
        if sw.locked && ! inp_locked { // Unlock operation (only SwapAdmin)
            let admin_role = has_role(&acc_auth, Role::SwapAdmin, acc_admn.key);
            if admin_role.is_err() {
                msg!("No swap admin role");
                return Err(ErrorCode::AccessDenied.into());
            }
        } else if sw.locked {
            msg!("Swap data locked");
            return Err(ErrorCode::AccessDenied.into());
        } else {
            let admin_role = has_role(&acc_auth, Role::SwapUpdate, acc_admn.key);
            if admin_role.is_err() {
                msg!("No swap update role");
                return Err(ErrorCode::AccessDenied.into());
            }
        }

        sw.locked = inp_locked;
        sw.oracle_verify = inp_oracle_verify;
        sw.oracle_verify_min = inp_verify_min;
        sw.oracle_verify_max = inp_verify_max;
        sw.rate_swap = inp_swap_rate;
        sw.rate_base = inp_base_rate;
        sw.fees_bps = inp_fees_bps;

        Ok(())
    }

    pub fn update_swap_active(ctx: Context<UpdateSwap>,
        inp_root_nonce: u8,         // RootData nonce
        inp_active: bool,           // Active flag
        inp_global: bool,           // Global setting
    ) -> ProgramResult {
        let acc_admn = &ctx.accounts.swap_admin.to_account_info(); // SwapAbort or SwapAdmin role
        let acc_root = &ctx.accounts.root_data.to_account_info();
        let acc_auth = &ctx.accounts.auth_data.to_account_info();

        // Verify program data
        let acc_root_expected = Pubkey::create_program_address(&[ctx.program_id.as_ref(), &[inp_root_nonce]], ctx.program_id)
            .map_err(|_| ErrorCode::InvalidDerivedAccount)?;
        verify_matching_accounts(acc_root.key, &acc_root_expected, Some(String::from("Invalid root data")))?;
        verify_matching_accounts(acc_auth.key, &ctx.accounts.root_data.root_authority, Some(String::from("Invalid root authority")))?;

        if inp_active {
            let admin_role = has_role(&acc_auth, Role::SwapAdmin, acc_admn.key);
            if admin_role.is_err() {
                msg!("No swap admin role");
                return Err(ErrorCode::AccessDenied.into());
            }
        } else {
            let admin_role = has_role(&acc_auth, Role::SwapAbort, acc_admn.key);
            if admin_role.is_err() {
                msg!("No swap abort role");
                return Err(ErrorCode::AccessDenied.into());
            }
        }

        let sw = &mut ctx.accounts.swap_data;
        sw.active = inp_active;

        if inp_global {
            let rt = &mut ctx.accounts.root_data;
            rt.active = inp_active;
        }

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
        let spl_token: Pubkey = Pubkey::from_str(SPL_TOKEN).unwrap();
        let asc_token: Pubkey = Pubkey::from_str(ASC_TOKEN).unwrap();
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
        msg!("atellix-log");
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
        let spl_token: Pubkey = Pubkey::from_str(SPL_TOKEN).unwrap();
        let asc_token: Pubkey = Pubkey::from_str(ASC_TOKEN).unwrap();
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
        msg!("atellix-log");
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

        // Verify withdrawal permit
        let permit_role = has_role(&acc_auth, Role::SwapPermit, acc_tdst.key);
        if permit_role.is_err() {
            msg!("No swap permit role");
            return Err(ErrorCode::AccessDenied.into());
        }

        // Verify swap associated token
        let spl_token: Pubkey = Pubkey::from_str(SPL_TOKEN).unwrap();
        let asc_token: Pubkey = Pubkey::from_str(ASC_TOKEN).unwrap();
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
        msg!("atellix-log");
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

    pub fn swap<'info>(ctx: Context<'_, '_, '_, 'info, Swap<'info>>,
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
        verify_program_data(inp_root_nonce, acc_root.key, &ctx.program_id)?;
        verify_matching_accounts(acc_auth.key, &ctx.accounts.root_data.root_authority, Some(String::from("Invalid root authority")))?;

        // Verify swap token info and fees token
        let acc_inb = &ctx.accounts.inb_info.to_account_info();
        let acc_out = &ctx.accounts.out_info.to_account_info();
        let acc_fee = &ctx.accounts.fees_token.to_account_info();
        let sw = &ctx.accounts.swap_data;
        let rt = &ctx.accounts.root_data;
        if !(sw.active && rt.active) {
            msg!("Inactive swap");
            return Err(ErrorCode::AccessDenied.into());
        }
        verify_matching_accounts(&sw.fees_token, acc_fee.key, Some(String::from("Invalid fees token")))?;
        verify_matching_accounts(&sw.inb_token_info, acc_inb.key, Some(String::from("Invalid inbound token info")))?;
        verify_matching_accounts(&sw.out_token_info, acc_out.key, Some(String::from("Invalid outbound token info")))?;
        let inb_info = &mut ctx.accounts.inb_info;
        let out_info = &mut ctx.accounts.out_info;

        let acc_inb_token_src = ctx.accounts.inb_token_src.to_account_info();
        let acc_inb_token_dst = ctx.accounts.inb_token_dst.to_account_info();
        let acc_out_token_src = ctx.accounts.out_token_src.to_account_info();
        let acc_out_token_dst = ctx.accounts.out_token_dst.to_account_info();

        // Verify inbound dest associated token
        let spl_token: Pubkey = Pubkey::from_str(SPL_TOKEN).unwrap();
        let asc_token: Pubkey = Pubkey::from_str(ASC_TOKEN).unwrap();
        let derived_key_in = Pubkey::create_program_address(
            &[
                &acc_root.key.to_bytes(),
                &spl_token.to_bytes(),
                &inb_info.mint.to_bytes(),
                &[inp_inb_nonce]
            ],
            &asc_token
        ).map_err(|_| {
            msg!("Invalid derived account");
            ErrorCode::InvalidDerivedAccount
        })?;
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

        // Verify merchant approval for merchant swaps
        let mut merchant_revenue: u64 = 0;
        let mut merchant_offset: usize = 0;
        if sw.merchant_only {
            msg!("Merchant-only Swap");
            if sw.oracle_rates || sw.oracle_verify {
                merchant_offset = 1;
            }
            let acc_mrch_approval = ctx.remaining_accounts.get(merchant_offset).unwrap();
            let netauth_role = has_role(&acc_auth, Role::NetworkAuth, acc_mrch_approval.owner);
            if netauth_role.is_err() {
                msg!("Invalid network authority");
                return Err(ErrorCode::AccessDenied.into());
            }
            let mut aprv_data: &[u8] = &acc_mrch_approval.try_borrow_data()?;
            let mrch_approval = MerchantApproval::try_deserialize(&mut aprv_data)?;
            if ! mrch_approval.active {
                msg!("Inactive merchant approval");
                return Err(ErrorCode::AccessDenied.into());
            }
            let (mrch_token, _bump_seed) = Pubkey::find_program_address(
                &[
                    mrch_approval.merchant_key.as_ref(),
                    spl_token.as_ref(),
                    mrch_approval.token_mint.as_ref(),
                ],
                &asc_token,
            );
            verify_matching_accounts(acc_inb_token_src.key, &mrch_token, Some(String::from("Invalid merchant associated token")))?;
            merchant_revenue = mrch_approval.revenue;
            //msg!("Atellix: Merchant Revenue: {}", merchant_revenue.to_string());
        }

        let mut oracle_val: f64 = 0.0;
        let mut oracle_log_inuse: bool = false;
        let mut oracle_log_val: u128 = 0;
        let mut extra_decimals: u128 = 0;
        let adjust_u: u32 = 8; // Calculate to 8 decimal places
        let adjust_i: i32 = 8;
        let base_u: u128 = 10;
        let base_f: f64 = 10.0;
        if sw.oracle_rates || sw.oracle_verify {
            let acc_orac = ctx.remaining_accounts.get(0).unwrap();
            verify_matching_accounts(acc_orac.key, &sw.oracle_data, Some(String::from("Invalid oracle data")))?;
            oracle_log_inuse = true;
            let oracle_type = OracleType::try_from(sw.oracle_type).unwrap();
            if oracle_type == OracleType::Switchboard {
                let feed_data = FastRoundResultAccountData::deserialize(&acc_orac.try_borrow_data()?).unwrap();
                oracle_val = feed_data.result.result;
            } else {
                msg!("Invalid oracle type");
                return Err(ErrorCode::InternalError.into());
            }
            //msg!("Atellix: Orcl: {}", oracle_val.to_string());
            let oracle_adj: f64 = oracle_val * base_f.powi(adjust_i);
            oracle_log_val = oracle_adj as u128;
            extra_decimals = base_u.pow(adjust_u);
            //msg!("Atellix: Extra decimals: {}", extra_decimals.to_string());
        }

        if sw.oracle_verify { // Check for valid oracle range before proceeding
            let oracle_adj2: f64 = oracle_val * base_f.powi(6);
            let oracle_dcm: u64 = oracle_adj2 as u64;
            //msg!("Atellix: Orcl Verify: {} Min: {} Max: {}", oracle_dcm.to_string(), sw.oracle_verify_min.to_string(), sw.oracle_verify_max.to_string());
            if sw.oracle_verify_min > 0 && sw.oracle_verify_min > oracle_dcm {
                msg!("Oracle result: {} below minimum: {}", oracle_dcm.to_string(), sw.oracle_verify_min.to_string());
                return Err(ErrorCode::OracleOutOfRange.into());
            }
            if sw.oracle_verify_max > 0 && sw.oracle_verify_max < oracle_dcm {
                msg!("Oracle result: {} above maximum: {}", oracle_dcm.to_string(), sw.oracle_verify_max.to_string());
                return Err(ErrorCode::OracleOutOfRange.into());
            }
        }

        //msg!("Atellix: Tokens verified ready to swap");
        let mut swap_rate: u128 = sw.rate_swap as u128;
        let mut base_rate: u128 = sw.rate_base as u128;
        if sw.oracle_rates {
            //msg!("Atellix: Use oracle rates");
            let in_decimals: i32 = inb_info.decimals as i32;
            let out_decimals: i32 = out_info.decimals as i32;
            let mut abs_decimals: i32 = in_decimals.checked_sub(out_decimals).ok_or(ProgramError::from(ErrorCode::Overflow))?;
            abs_decimals = abs_decimals.abs();
            let abs_decimals_u: u32 = u32::try_from(abs_decimals).map_err(|_| ErrorCode::Overflow)?;
            let adjust_decimals: u128 = base_u.checked_pow(abs_decimals_u).ok_or(ProgramError::from(ErrorCode::Overflow))?;
            if sw.oracle_inverse {
                //msg!("Atellix: Inverse oracle");
                if (sw.oracle_max && oracle_log_val > swap_rate) || ! sw.oracle_max {
                    swap_rate = oracle_log_val;
                }
                base_rate = adjust_decimals;
            } else {
                swap_rate = adjust_decimals;
                if (sw.oracle_max && oracle_log_val > base_rate) || ! sw.oracle_max {
                    base_rate = oracle_log_val;
                }
            }
        }
        //msg!("Atellix: Rates - Swap: {} Base: {}", swap_rate.to_string(), base_rate.to_string());
        let input_val: u128 = inp_tokens as u128;
        let result: u128 = calculate_swap(sw, inp_is_buy, input_val, swap_rate, base_rate, extra_decimals)?;
        //msg!("Atellix: Result: {}", result.to_string());

        let tokens_inb: u64;
        let tokens_out: u64;
        if inp_is_buy {
            tokens_inb = u64::try_from(result).map_err(|_| ErrorCode::Overflow)?;
            tokens_out = inp_tokens;
        } else {
            tokens_inb = inp_tokens;
            tokens_out = u64::try_from(result).map_err(|_| ErrorCode::Overflow)?;
        }
        let tokens_fee: u64 = calculate_fee(sw, inp_is_buy, input_val, swap_rate, base_rate, extra_decimals)?;

        /*msg!("Atellix: Inb: {} Out: {}", tokens_inb.to_string(), tokens_out.to_string());
        if sw.fees_inbound {
            msg!("Atellix: Fee Inb: {}", tokens_fee.to_string());
        } else {
            msg!("Atellix: Fee Out: {}", tokens_fee.to_string());
        }*/

        if sw.merchant_only {
            if tokens_inb > merchant_revenue {
                msg!("Atellix: Inbound token exceeds merchant balance");
                return Err(ErrorCode::Overflow.into());
            }

            // Record merchant revenue
            let seeds = &[ctx.program_id.as_ref(), &[inp_root_nonce]];
            let signer = &[&seeds[..]];
            let na_program = ctx.remaining_accounts.get(merchant_offset + 1).unwrap(); // NetAuthority Program
            let na_accounts = RecordRevenue {
                root_data: ctx.remaining_accounts.get(merchant_offset + 2).unwrap().clone(), // NetAuthority Root Data
                auth_data: ctx.remaining_accounts.get(merchant_offset + 3).unwrap().clone(), // NetAuthority Auth Data
                revenue_admin: ctx.accounts.root_data.to_account_info(),
                merchant_approval: ctx.remaining_accounts.get(merchant_offset).unwrap().clone(),
            };
            let na_ctx = CpiContext::new_with_signer(na_program.clone(), na_accounts, signer);
            let (_addr, net_nonce) = Pubkey::find_program_address(&[na_program.key.as_ref()], na_program.key);
 
            //msg!("Atellix: Attempt to record revenue withdrawal");
            net_authority::cpi::record_revenue(na_ctx, net_nonce, false, tokens_inb)?;
        }

        //msg!("Atellix: Available Outbound Tokens: {}", out_info.amount.to_string());
        inb_info.amount = inb_info.amount.checked_add(tokens_inb).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        out_info.amount = out_info.amount.checked_sub(tokens_out).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        if sw.fees_inbound {
            inb_info.amount = inb_info.amount.checked_sub(tokens_fee).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        } else {
            out_info.amount = out_info.amount.checked_sub(tokens_fee).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        }

        //msg!("Atellix: New Inbound Amount: {}", inb_info.amount.to_string());
        //msg!("Atellix: New Outbound Amount: {}", out_info.amount.to_string());

        let in_accounts = Transfer {
            from: acc_inb_token_src,
            to: acc_inb_token_dst,
            authority: ctx.accounts.swap_user.to_account_info(),
        };
        let cpi_prog1 = ctx.accounts.token_program.clone();
        let in_ctx = CpiContext::new(cpi_prog1, in_accounts);
        //msg!("Atellix: Attempt Inbound Transfer");
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
        //msg!("Atellix: Attempt Outbound Transfer");
        token::transfer(out_ctx, tokens_out)?;

        if tokens_fee > 0 {
            if sw.fees_inbound {
                let fees_seeds = &[
                    ctx.program_id.as_ref(),
                    &[inp_root_nonce],
                ];
                let fees_signer = &[&fees_seeds[..]];
                let fees_accounts = Transfer {
                    from: ctx.accounts.inb_token_dst.clone(),
                    to: ctx.accounts.fees_token.to_account_info(),
                    authority: ctx.accounts.root_data.to_account_info(),
                };
                let cpi_prog = ctx.accounts.token_program.clone();
                let fees_ctx = CpiContext::new_with_signer(cpi_prog, fees_accounts, fees_signer);
                //msg!("Atellix: Attempt Fees Transfer - Inbound Token");
                token::transfer(fees_ctx, tokens_fee)?;
            } else {
                let fees_seeds = &[
                    ctx.program_id.as_ref(),
                    &[inp_root_nonce],
                ];
                let fees_signer = &[&fees_seeds[..]];
                let fees_accounts = Transfer {
                    from: ctx.accounts.out_token_src.clone(),
                    to: ctx.accounts.fees_token.to_account_info(),
                    authority: ctx.accounts.root_data.to_account_info(),
                };
                let cpi_prog = ctx.accounts.token_program.clone();
                let fees_ctx = CpiContext::new_with_signer(cpi_prog, fees_accounts, fees_signer);
                //msg!("Atellix: Attempt Fees Transfer - Outbound Token");
                token::transfer(fees_ctx, tokens_fee)?;
            }
        }

        let clock = Clock::get()?;
        inb_info.token_tx_count = inb_info.token_tx_count.checked_add(1).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        out_info.token_tx_count = out_info.token_tx_count.checked_add(1).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        inb_info.slot = clock.slot;
        out_info.slot = clock.slot;
        let swp = &mut ctx.accounts.swap_data;
        swp.swap_tx_count = swp.swap_tx_count.checked_add(1).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        swp.swap_inb_tokens = swp.swap_inb_tokens.checked_add(tokens_inb).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        swp.swap_out_tokens = swp.swap_out_tokens.checked_add(tokens_out).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        swp.fees_total = swp.fees_total.checked_add(tokens_fee).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        swp.inb_token_tx = inb_info.token_tx_count;
        swp.out_token_tx = out_info.token_tx_count;
        swp.slot = clock.slot;

        msg!("atellix-log");
        emit!(SwapEvent {
            event_hash: 144834217477609949185867766428666600068, // "solana/program/atx-swap-contract/swap" (MurmurHash3 128-bit unsigned)
            slot: clock.slot,
            swap_data: ctx.accounts.swap_data.key(),
            user: ctx.accounts.swap_user.key(),
            inb_tokens: tokens_inb,
            inb_token_src: ctx.accounts.inb_token_src.key(),
            out_tokens: tokens_out,
            out_token_dst: ctx.accounts.out_token_dst.key(),
            fees_inbound: ctx.accounts.swap_data.fees_inbound,
            fees_amount: tokens_fee,
            fees_token: ctx.accounts.swap_data.fees_token,
            use_oracle: oracle_log_inuse,
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
    pub program: AccountInfo<'info>,
    pub program_data: AccountInfo<'info>,
    #[account(signer)]
    pub program_admin: AccountInfo<'info>,
    #[account(address = system_program::ID)]
    pub system_program: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct UpdateMetadata<'info> {
    pub program: AccountInfo<'info>,
    pub program_data: AccountInfo<'info>,
    #[account(signer)]
    pub program_admin: AccountInfo<'info>,
    #[account(mut)]
    pub program_info: AccountInfo<'info>,
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
    pub fees_token: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct UpdateSwap<'info> {
    pub root_data: ProgramAccount<'info, RootData>,
    pub auth_data: AccountInfo<'info>,
    #[account(signer)]
    pub swap_admin: AccountInfo<'info>,
    #[account(mut)]
    pub swap_data: ProgramAccount<'info, SwapData>,
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
    pub locked: bool,                   // Locked flag (prevents updates)
    pub slot: u64,                      // Last slot updated
    pub merchant_only: bool,            // Merchant-only flag
    pub oracle_data: Pubkey,            // Oracle data address or Pubkey::default() for none
    pub oracle_type: u8,                // Oracle data type
    pub oracle_rates: bool,             // Uses oracle data for swap rates
    pub oracle_max: bool,               // Uses oracle data if greater
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
    pub active: bool,
}

impl RootData {
    pub fn active(&self) -> bool {
        self.active
    }

    pub fn root_authority(&self) -> Pubkey {
        self.root_authority
    }

    pub fn set_active(&mut self, new_active: bool) {
        self.active = new_active
    }

    pub fn set_root_authority(&mut self, new_authority: Pubkey) {
        self.root_authority = new_authority
    }
}

impl Default for RootData {
    fn default() -> Self {
        Self {
            root_authority: Pubkey::default(),
            active: true,
        }
    }
}

#[event]
pub struct SwapEvent {
    pub event_hash: u128,
    pub slot: u64,
    pub swap_data: Pubkey,
    pub user: Pubkey,
    pub inb_tokens: u64,
    pub inb_token_src: Pubkey,
    pub out_tokens: u64,
    pub out_token_dst: Pubkey,
    pub fees_inbound: bool,
    pub fees_amount: u64,
    pub fees_token: Pubkey,
    pub use_oracle: bool,
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

#[account]
pub struct ProgramMetadata {
    pub semvar_major: u32,
    pub semvar_minor: u32,
    pub semvar_patch: u32,
    pub program: Pubkey,
    pub program_name: String,   // Max len 64
    pub developer_name: String, // Max len 64
    pub developer_url: String,  // Max len 128
    pub source_url: String,     // Max len 128
    pub verify_url: String,     // Max len 128
}
// 8 + (4 * 3) + (4 * 5) + (64 * 2) + (128 * 3) + 32
// Data length (with discrim): 584 bytes

#[error]
pub enum ErrorCode {
    #[msg("Access denied")]
    AccessDenied,
    #[msg("Oracle out of range")]
    OracleOutOfRange,
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

