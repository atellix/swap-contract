use crate::program::SwapContract;
use std::{ string::String, result::Result as FnResult, convert::TryFrom };
use bytemuck::{ Pod, Zeroable };
use byte_slice_cast::*;
use num_enum::{ TryFromPrimitive, IntoPrimitive };
use switchboard_program;
use switchboard_program::{ FastRoundResultAccountData };
use anchor_lang::prelude::*;
use anchor_spl::token::{ self, Token, Mint, TokenAccount, MintTo, Transfer };
use anchor_spl::associated_token::{ AssociatedToken };
use solana_program::{
    account_info::AccountInfo,
    clock::Clock
};

use net_authority::{ cpi::accounts::RecordRevenue, MerchantApproval };

extern crate slab_alloc;
use slab_alloc::{ SlabPageAlloc, CritMapHeader, CritMap, AnyNode, LeafNode, SlabVec, SlabTreeError };

declare_id!("6GHsmynfJxQMY65rEspjacpXDPPmwQqJbdFhxfZEG2zz");

pub const VERSION_MAJOR: u32 = 1;
pub const VERSION_MINOR: u32 = 0;
pub const VERSION_PATCH: u32 = 0;

pub const MAX_RBAC: u32 = 128;

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

fn calculate_rates(td: &TokenData, sw: &SwapData, swap_rate: &mut u128, base_rate: &mut u128, extra_decimals: &mut u128, oracle_log_val: u128) -> ProgramResult {
    let adjust_u: u32 = 8; // Calculate to 8 decimal places
    let base_u: u128 = 10;
    if td.basis_rates {
        //msg!("Atellix: Use basis rates");
        let mut tokens_outstanding: i128 = sw.tokens_outstanding.checked_add(sw.tokens_offset).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        let tokens_cost: i128 = sw.cost_basis.checked_add(sw.cost_offset).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        // Calculate basis price and multiply time 10^8 to compare to oracle prices
        let base_i: i128 = 10;
        let cost_decimals: i128 = base_i.pow(adjust_u);
        tokens_outstanding = tokens_outstanding.checked_mul(cost_decimals).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        tokens_outstanding = tokens_outstanding.checked_div(tokens_cost).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        let basis_price: u128 = u128::try_from(tokens_outstanding).map_err(|_| ErrorCode::Overflow)?;
        if basis_price == 0 {
            return Err(ErrorCode::Overflow.into());
        }
        if td.oracle_rates {
            *extra_decimals = u128::try_from(cost_decimals).map_err(|_| ErrorCode::Overflow)?;
            //msg!("Atellix: Extra decimals: {}", extra_decimals.to_string());
            let in_decimals: i32 = sw.inb_token_data.decimals as i32;
            let out_decimals: i32 = sw.out_token_data.decimals as i32;
            let mut abs_decimals: i32 = in_decimals.checked_sub(out_decimals).ok_or(ProgramError::from(ErrorCode::Overflow))?;
            abs_decimals = abs_decimals.abs();
            let abs_decimals_u: u32 = u32::try_from(abs_decimals).map_err(|_| ErrorCode::Overflow)?;
            let adjust_decimals: u128 = base_u.checked_pow(abs_decimals_u).ok_or(ProgramError::from(ErrorCode::Overflow))?;
            if td.oracle_inverse {
                *swap_rate = basis_price;
                if td.oracle_max && oracle_log_val > *swap_rate {
                    *swap_rate = oracle_log_val;
                }
                *base_rate = adjust_decimals;
            } else {
                *swap_rate = adjust_decimals;
                *base_rate = basis_price;
                if td.oracle_max && oracle_log_val > *base_rate {
                    *base_rate = oracle_log_val;
                }
            }
        } else {
            *base_rate = basis_price;
            *swap_rate = u128::try_from(cost_decimals).map_err(|_| ErrorCode::Overflow)?;
        }
    } else if td.oracle_rates {
        //msg!("Atellix: Use oracle rates");
        *extra_decimals = base_u.pow(adjust_u);
        //msg!("Atellix: Extra decimals: {}", extra_decimals.to_string());
        let in_decimals: i32 = sw.inb_token_data.decimals as i32;
        let out_decimals: i32 = sw.out_token_data.decimals as i32;
        let mut abs_decimals: i32 = in_decimals.checked_sub(out_decimals).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        abs_decimals = abs_decimals.abs();
        let abs_decimals_u: u32 = u32::try_from(abs_decimals).map_err(|_| ErrorCode::Overflow)?;
        let adjust_decimals: u128 = base_u.checked_pow(abs_decimals_u).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        if td.oracle_inverse {
            //msg!("Atellix: Inverse oracle");
            if (td.oracle_max && oracle_log_val > *swap_rate) || ! td.oracle_max {
                *swap_rate = oracle_log_val;
            }
            *base_rate = adjust_decimals;
        } else {
            *swap_rate = adjust_decimals;
            if (td.oracle_max && oracle_log_val > *base_rate) || ! td.oracle_max {
                *base_rate = oracle_log_val;
            }
        }
    }
    Ok(())
}

fn calculate_swap(
    td: &TokenData,
    is_buy: bool,
    input_val: u128,
    swap_rate: u128,
    base_rate: u128,
    extra_decimals: u128,
    merchant: bool,
) -> FnResult<u128, ProgramError> {
    let nmr_1: u128;
    let fees_bps: u32 = if merchant { 0 } else { td.fees_bps };
    if fees_bps > 0 {
        let mut fee_part: u128 = input_val.checked_mul(fees_bps as u128).ok_or(ProgramError::from(ErrorCode::Overflow))?;
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
    if td.oracle_rates { 
        if td.oracle_inverse {
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

fn calculate_fee(
    td: &TokenData,
    inbound_fees: bool,
    is_buy: bool,
    input_val: u128,
    swap_rate: u128,
    base_rate: u128,
    extra_decimals: u128,
    merchant: bool,
) -> FnResult<u64, ProgramError> {
    let mut top_pow: bool = false; // Use extra_decimals for actual value
    let mut btm_pow: bool = false;
    let fees_bps: u32 = if merchant { 0 } else { td.fees_bps };
    if fees_bps > 0 {
        let mut fee_1 = input_val.checked_mul(fees_bps as u128).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        fee_1 = fee_1.checked_div(10000).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        if inbound_fees { // Fees on inbound token
            if td.oracle_rates && is_buy {
                if td.oracle_inverse {
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
            if td.oracle_rates && ! is_buy {
                if td.oracle_inverse {
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

pub fn update_swap_result(ctx: Context<Swap>, swap_direction: bool, tokens_inb: u64, tokens_out: u64, tokens_fee: u64, slot: u64) -> ProgramResult {
    let swp = &mut ctx.accounts.swap_data;
    if swap_direction {
        swp.inb_token_data.amount = swp.inb_token_data.amount.checked_add(tokens_inb).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        swp.out_token_data.amount = swp.out_token_data.amount.checked_sub(tokens_out).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        swp.cost_basis = swp.cost_basis.checked_add(tokens_inb as i128).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        swp.tokens_outstanding = swp.tokens_outstanding.checked_add(tokens_out as i128).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        if !swp.fees_inbound {
            swp.tokens_outstanding = swp.tokens_outstanding.checked_add(tokens_fee as i128).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        }
    } else {
        swp.inb_token_data.amount = swp.inb_token_data.amount.checked_sub(tokens_out).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        swp.out_token_data.amount = swp.out_token_data.amount.checked_add(tokens_inb).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        swp.cost_basis = swp.cost_basis.checked_sub(tokens_out as i128).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        swp.tokens_outstanding = swp.tokens_outstanding.checked_sub(tokens_inb as i128).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        if swp.fees_inbound {
            swp.cost_basis = swp.cost_basis.checked_sub(tokens_fee as i128).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        }
    }
    if swp.fees_inbound {
        swp.inb_token_data.amount = swp.inb_token_data.amount.checked_sub(tokens_fee).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        swp.inb_token_data.fees_total = swp.inb_token_data.fees_total.checked_add(tokens_fee).ok_or(ProgramError::from(ErrorCode::Overflow))?;
    } else {
        swp.out_token_data.amount = swp.out_token_data.amount.checked_sub(tokens_fee).ok_or(ProgramError::from(ErrorCode::Overflow))?;
        swp.out_token_data.fees_total = swp.out_token_data.fees_total.checked_add(tokens_fee).ok_or(ProgramError::from(ErrorCode::Overflow))?;
    }
    swp.swap_tx_count = swp.swap_tx_count.checked_add(1).ok_or(ProgramError::from(ErrorCode::Overflow))?;
    swp.slot = slot;
    Ok(())
}

#[program]
pub mod swap_contract {
    use super::*;
    pub fn initialize(ctx: Context<Initialize>) -> ProgramResult {
        let rt = &mut ctx.accounts.root_data;
        rt.root_authority = ctx.accounts.auth_data.key();

        let auth_data: &mut[u8] = &mut ctx.accounts.auth_data.try_borrow_mut_data()?;
        let rd = SlabPageAlloc::new(auth_data);
        rd.setup_page_table();
        rd.allocate::<CritMapHeader, AnyNode>(DT::UserRBACMap as u16, MAX_RBAC as usize).expect("Failed to allocate");
        rd.allocate::<SlabVec, UserRBAC>(DT::UserRBAC as u16, MAX_RBAC as usize).expect("Failed to allocate");

        Ok(())
    }

    pub fn store_metadata(ctx: Context<UpdateMetadata>,
        inp_program_name: String,
        inp_developer_name: String,
        inp_developer_url: String,
        inp_source_url: String,
        inp_verify_url: String,
    ) -> ProgramResult {
        let md = &mut ctx.accounts.program_info;
        md.semvar_major = VERSION_MAJOR;
        md.semvar_minor = VERSION_MINOR;
        md.semvar_patch = VERSION_PATCH;
        md.program = ctx.accounts.program.key();
        md.program_name = inp_program_name;
        md.developer_name = inp_developer_name;
        md.developer_url = inp_developer_url;
        md.source_url = inp_source_url;
        md.verify_url = inp_verify_url;
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
        _inp_root_nonce: u8,
        inp_role: u32,
    ) -> ProgramResult {
        let acc_rbac = &ctx.accounts.rbac_user.to_account_info();
        let acc_admn = &ctx.accounts.program_admin.to_account_info();
        let acc_auth = &ctx.accounts.auth_data.to_account_info();

        // Check for NetworkAdmin authority
        let admin_role = has_role(&acc_auth, Role::NetworkAdmin, acc_admn.key);
        let mut program_owner: bool = false;
        if admin_role.is_err() {
            let acc_pdat = &ctx.accounts.program_data;
            verify_matching_accounts(&acc_pdat.upgrade_authority_address.unwrap(), acc_admn.key, Some(String::from("Invalid program owner")))?;
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
        _inp_root_nonce: u8,
        inp_role: u32,
    ) -> ProgramResult {
        let acc_admn = &ctx.accounts.program_admin.to_account_info(); // Program owner or network admin
        let acc_auth = &ctx.accounts.auth_data.to_account_info();
        let acc_rbac = &ctx.accounts.rbac_user.to_account_info();

        // Check for NetworkAdmin authority
        let admin_role = has_role(&acc_auth, Role::NetworkAdmin, acc_admn.key);
        let mut program_owner: bool = false;
        if admin_role.is_err() {
            let acc_pdat = &ctx.accounts.program_data;
            verify_matching_accounts(&acc_pdat.upgrade_authority_address.unwrap(), acc_admn.key, Some(String::from("Invalid program owner")))?;
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

    pub fn create_swap(ctx: Context<CreateSwap>,
        inp_root_nonce: u8,             // RootData nonce
        inp_swpd_nonce: u8,             // SwapData nonce
        inp_oracle_verify: bool,        // Use oracle to verify price range (to check peg stability on stablecoins)
        inp_oracle_type: u8,            // Use oracle type
        inp_verify_min: u64,            // Minimum of price range (0 for unused)
        inp_verify_max: u64,            // Maximum of price range (0 for unused)
        inp_fees_inbound: bool,         // Take fees from inbound token (alternatively use the outbound token)
        // Inbound tokens
        inp_inb_decimals: u8,           // Decimals
        inp_inb_basis_rates: bool,      // Uses cost-basis rates
        inp_inb_oracle_rates: bool,     // Uses oracle data for swap rates
        inp_inb_oracle_max: bool,       // Uses oracle data if greater
        inp_inb_oracle_inverse: bool,   // Inverse the oracle rate
        inp_inb_fees_bps: u32,          // Swap fees in basis points
        inp_inb_rate_swap: u64,         // Swap rate
        inp_inb_rate_base: u64,         // Base rate
        // Outbound tokens
        inp_out_decimals: u8,           // Decimals
        inp_out_basis_rates: bool,      // Uses cost-basis rates
        inp_out_oracle_rates: bool,     // Uses oracle data for swap rates
        inp_out_oracle_max: bool,       // Uses oracle data if greater
        inp_out_oracle_inverse: bool,   // Inverse the oracle rate
        inp_out_fees_bps: u32,          // Swap fees in basis points
        inp_out_rate_swap: u64,         // Swap rate
        inp_out_rate_base: u64,         // Base rate
    ) -> ProgramResult {
        let acc_admn = &ctx.accounts.swap_admin.to_account_info(); // Swap admin
        let acc_swap = &ctx.accounts.swap_data.to_account_info(); 
        let acc_root = &ctx.accounts.root_data.to_account_info();
        let acc_auth = &ctx.accounts.auth_data.to_account_info();
        let acc_inb = &ctx.accounts.inb_mint.to_account_info();
        let acc_out = &ctx.accounts.out_mint.to_account_info();
        //let acc_sys = &ctx.accounts.system_program.to_account_info();

        // Verify program data
        let acc_root_expected = Pubkey::create_program_address(&[ctx.program_id.as_ref(), &[inp_root_nonce]], ctx.program_id)
            .map_err(|_| ErrorCode::InvalidDerivedAccount)?;
        verify_matching_accounts(acc_root.key, &acc_root_expected, Some(String::from("Invalid root data")))?;
        verify_matching_accounts(acc_auth.key, &ctx.accounts.root_data.root_authority, Some(String::from("Invalid root authority")))?;

        // Verify swap data
        let acc_swpd_expected = Pubkey::create_program_address(&[acc_inb.key.as_ref(), acc_out.key.as_ref(), &[inp_swpd_nonce]], ctx.program_id)
            .map_err(|_| ErrorCode::InvalidDerivedAccount)?;
        verify_matching_accounts(acc_swap.key, &acc_swpd_expected, Some(String::from("Invalid swap data")))?;

        let admin_role = has_role(&acc_auth, Role::SwapAdmin, acc_admn.key);
        if admin_role.is_err() {
            msg!("No swap admin role");
            return Err(ErrorCode::AccessDenied.into());
        }

        if *acc_inb.key == *acc_out.key {
            msg!("Both tokens cannot have the same mint");
            return Err(ErrorCode::InvalidParameters.into());
        }

        OracleType::try_from(inp_oracle_type).map_err(|_| {
            msg!("Invalid oracle type");
            ErrorCode::InvalidParameters
        })?;

        let mut oracle: Pubkey = Pubkey::default();
        if inp_inb_oracle_rates || inp_out_oracle_rates || inp_oracle_verify {
            let acc_orac = ctx.remaining_accounts.get(0).unwrap();
            oracle = *acc_orac.key;
        }

        let inb_token = TokenData {
            basis_rates: inp_inb_basis_rates,
            oracle_rates: inp_inb_oracle_rates,
            oracle_max: inp_inb_oracle_max,
            oracle_inverse: inp_inb_oracle_inverse,
            rate_swap: inp_inb_rate_swap,
            rate_base: inp_inb_rate_base,
            decimals: inp_inb_decimals,
            fees_bps: inp_inb_fees_bps,
            fees_total: 0,
            amount: 0,
        };
        let out_token = TokenData {
            basis_rates: inp_out_basis_rates,
            oracle_rates: inp_out_oracle_rates,
            oracle_max: inp_out_oracle_max,
            oracle_inverse: inp_out_oracle_inverse,
            rate_swap: inp_out_rate_swap,
            rate_base: inp_out_rate_base,
            decimals: inp_out_decimals,
            fees_bps: inp_out_fees_bps,
            fees_total: 0,
            amount: 0,
        };

        let clock = Clock::get()?;
        let sw = &mut ctx.accounts.swap_data;
        sw.active = true;
        sw.locked = false;
        sw.slot = clock.slot;
        sw.oracle_data = oracle;
        sw.oracle_type = inp_oracle_type;
        sw.oracle_verify = inp_oracle_verify;
        sw.oracle_verify_min = inp_verify_min;
        sw.oracle_verify_max = inp_verify_max;
        sw.inb_mint = *acc_inb.key;
        sw.inb_token_data = inb_token;
        sw.out_mint = *acc_out.key;
        sw.out_token_data = out_token;
        sw.fees_inbound = inp_fees_inbound;
        sw.fees_token = *ctx.accounts.fees_token.to_account_info().key;
        sw.swap_tx_count = 0;
        sw.tokens_outstanding = 0;
        sw.tokens_offset = 0;
        sw.cost_basis = 0;
        sw.cost_offset = 0;
        Ok(())
    }

    pub fn update_swap(ctx: Context<UpdateSwap>,
        _inp_root_nonce: u8,        // RootData nonce
        _inp_swpd_nonce: u8,        // SwapData nonce
        inp_locked: bool,           // Lock / unlock
        inp_oracle_verify: bool,    // Use oracle to verify price range (to check peg stability on stablecoins)
        inp_verify_min: u64,        // Minimum of price range (0 for unused)
        inp_verify_max: u64,        // Maximum of price range (0 for unused)
        inp_swap_direction: bool,   // Swap direction (true == inb, false = out)
        inp_basis_rates: bool,      // Use basis rates
        inp_oracle_rates: bool,     // Use oracle rates
        inp_oracle_max: bool,       // Use oracle max
        inp_oracle_inverse: bool,   // Oracle inverse
        inp_swap_rate: u64,         // Swap rate
        inp_base_rate: u64,         // Base rate
        inp_fees_bps: u32,          // Fees basis points
    ) -> ProgramResult {
        let acc_admn = &ctx.accounts.swap_admin.to_account_info(); // SwapUpdate role
        let acc_auth = &ctx.accounts.auth_data.to_account_info();
        let acc_inb = &ctx.accounts.inb_mint.to_account_info();
        let acc_out = &ctx.accounts.out_mint.to_account_info();

        let sw = &mut ctx.accounts.swap_data;
        verify_matching_accounts(acc_inb.key, &sw.inb_mint, Some(String::from("Invalid inbound mint")))?;
        verify_matching_accounts(acc_out.key, &sw.out_mint, Some(String::from("Invalid outbound mint")))?;

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
        let current_side = if inp_swap_direction { &mut sw.inb_token_data } else { &mut sw.out_token_data };
        current_side.basis_rates = inp_basis_rates;
        current_side.oracle_rates = inp_oracle_rates;
        current_side.oracle_max = inp_oracle_max;
        current_side.oracle_inverse = inp_oracle_inverse;
        current_side.rate_swap = inp_swap_rate;
        current_side.rate_base = inp_base_rate;
        current_side.fees_bps = inp_fees_bps;

        Ok(())
    }

    pub fn update_swap_active(ctx: Context<UpdateSwap>,
        inp_root_nonce: u8,         // RootData nonce
        inp_active: bool,           // Active flag
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

        Ok(())
    }

    pub fn mint_deposit(ctx: Context<MintDeposit>,
        _inp_root_nonce: u8,        // RootData nonce
        _inp_swpd_nonce: u8,        // Token Info nonce
        inp_tokn_nonce: u8,         // Associated token nonce
        inp_amount: u64,            // Amount to mint
        inp_inbound_token: bool,    // Apply to inbound token (otherwise outbound)
    ) -> ProgramResult {
        let acc_admn = &ctx.accounts.swap_admin.to_account_info(); // Swap admin
        let acc_tadm = &ctx.accounts.token_admin.to_account_info(); // Token mint authority
        let acc_auth = &ctx.accounts.auth_data.to_account_info();
        let acc_prog = &ctx.accounts.token_program.to_account_info();
        let acc_tokn = &ctx.accounts.swap_token.to_account_info();
        let acc_inb = &ctx.accounts.inb_mint.to_account_info();
        let acc_out = &ctx.accounts.out_mint.to_account_info();
        
        let admin_role = has_role(&acc_auth, Role::SwapDeposit, acc_admn.key);
        if admin_role.is_err() {
            msg!("No swap deposit role");
            return Err(ErrorCode::AccessDenied.into());
        }

        // Verify swap associated token
        let acc_mint;
        if inp_inbound_token {
            acc_mint = ctx.accounts.inb_mint.to_account_info();
        } else {
            acc_mint = ctx.accounts.out_mint.to_account_info();
        }
        let derived_key = Pubkey::create_program_address(
            &[&ctx.accounts.swap_data.to_account_info().key.to_bytes(), &Token::id().to_bytes(), &acc_mint.key.to_bytes(), &[inp_tokn_nonce]],
            &AssociatedToken::id(),
        ).map_err(|_| ErrorCode::InvalidDerivedAccount)?;
        verify_matching_accounts(acc_tokn.key, &derived_key, Some(String::from("Invalid swap token vault")))?;

        let clock = Clock::get()?;
        let sw = &mut ctx.accounts.swap_data;
        verify_matching_accounts(acc_inb.key, &sw.inb_mint, Some(String::from("Invalid inbound mint")))?;
        verify_matching_accounts(acc_out.key, &sw.out_mint, Some(String::from("Invalid outbound mint")))?;

        //msg!("Atellix: Attempt mint deposit: {}", inp_amount.to_string());
        let cpi_accounts = MintTo {
            mint: acc_mint.clone(),
            to: acc_tokn.clone(),
            authority: acc_tadm.clone(),
        };
        let cpi_program = acc_prog.to_account_info();
        let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);
        token::mint_to(cpi_ctx, inp_amount)?;

        let new_total;
        if inp_inbound_token { 
            let mut ti = sw.inb_token_data;
            ti.amount = ti.amount.checked_add(inp_amount).ok_or(ProgramError::from(ErrorCode::Overflow))?;
            sw.inb_token_data = ti;
            new_total = ti.amount;
        } else {
            let mut ti = sw.out_token_data;
            ti.amount = ti.amount.checked_add(inp_amount).ok_or(ProgramError::from(ErrorCode::Overflow))?;
            sw.out_token_data = ti;
            new_total = ti.amount;
        }
        sw.slot = clock.slot;

        //msg!("Atellix: New token amount: {}", ctx.accounts.token_info.amount.to_string());
        msg!("atellix-log");
        emit!(TransferEvent {
            event_hash: 86124742241384372364379956883437878997, // solana/program/atx-swap-contract/deposit_mint
            slot: clock.slot,
            user: acc_admn.key(),
            inbound_token: inp_inbound_token,
            swap_data: ctx.accounts.swap_data.key(),
            token_acct: Pubkey::default(),
            deposit: true,
            transfer: false,
            amount: inp_amount,
            new_total: new_total,
        });

        Ok(())
    }

    pub fn deposit(ctx: Context<TransferDeposit>,
        _inp_root_nonce: u8,         // RootData nonce
        _inp_swpd_nonce: u8,         // SwapData nonce
        inp_tokn_nonce: u8,         // Associated token nonce
        inp_amount: u64,            // Amount to mint
        inp_inbound_token: bool,    // Apply to inbound token (otherwise outbound)
    ) -> ProgramResult {
        let acc_auth = &ctx.accounts.auth_data.to_account_info();
        let acc_admn = &ctx.accounts.swap_admin.to_account_info(); // Swap admin
        let acc_tadm = &ctx.accounts.token_admin.to_account_info(); // Token mint or transfer authority
        let acc_tsrc = &ctx.accounts.token_src.to_account_info();
        let acc_prog = &ctx.accounts.token_program.to_account_info();
        let acc_swap = &ctx.accounts.swap_data.to_account_info();
        let acc_tokn = &ctx.accounts.swap_token.to_account_info();
        let acc_inb = &ctx.accounts.inb_mint.to_account_info();
        let acc_out = &ctx.accounts.out_mint.to_account_info();

        let admin_role = has_role(&acc_auth, Role::SwapDeposit, acc_admn.key);
        if admin_role.is_err() {
            msg!("No swap deposit role");
            return Err(ErrorCode::AccessDenied.into());
        }

        // Verify swap associated token
        let acc_mint;
        if inp_inbound_token {
            acc_mint = ctx.accounts.inb_mint.to_account_info();
        } else {
            acc_mint = ctx.accounts.out_mint.to_account_info();
        }
        let derived_key = Pubkey::create_program_address(
            &[&ctx.accounts.swap_data.to_account_info().key.to_bytes(), &Token::id().to_bytes(), &acc_mint.key.to_bytes(), &[inp_tokn_nonce]],
            &AssociatedToken::id(),
        ).map_err(|_| ErrorCode::InvalidDerivedAccount)?;
        verify_matching_accounts(acc_tokn.key, &derived_key, Some(String::from("Invalid swap token vault")))?;

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
        let sw = &mut ctx.accounts.swap_data;
        verify_matching_accounts(acc_inb.key, &sw.inb_mint, Some(String::from("Invalid inbound mint")))?;
        verify_matching_accounts(acc_out.key, &sw.out_mint, Some(String::from("Invalid outbound mint")))?;

        let new_total;
        if inp_inbound_token { 
            let mut ti = sw.inb_token_data;
            ti.amount = ti.amount.checked_add(inp_amount).ok_or(ProgramError::from(ErrorCode::Overflow))?;
            sw.inb_token_data = ti;
            new_total = ti.amount;
        } else {
            let mut ti = sw.out_token_data;
            ti.amount = ti.amount.checked_add(inp_amount).ok_or(ProgramError::from(ErrorCode::Overflow))?;
            sw.out_token_data = ti;
            new_total = ti.amount;
        }
        sw.slot = clock.slot;

        //msg!("Atellix: New token amount: {}", new_total.to_string());
        msg!("atellix-log");
        emit!(TransferEvent {
            event_hash: 46880124277820728117333064135303940398, // solana/program/atx-swap-contract/deposit_transfer
            slot: clock.slot,
            user: acc_admn.key(),
            inbound_token: inp_inbound_token,
            swap_data: acc_swap.key(),
            token_acct: acc_tsrc.key(),
            deposit: true,
            transfer: true,
            amount: inp_amount,
            new_total: new_total,
        });

        Ok(())
    }

    pub fn withdraw(ctx: Context<Withdraw>,
        _inp_root_nonce: u8,         // RootData nonce
        inp_swpd_nonce: u8,         // SwapData nonce
        inp_tokn_nonce: u8,         // Associated token nonce
        inp_amount: u64,            // Amount to mint
        inp_inbound_token: bool,    // Apply to inbound token (otherwise outbound)
    ) -> ProgramResult {
        let acc_admn = &ctx.accounts.swap_admin.to_account_info(); // Swap admin
        let acc_auth = &ctx.accounts.auth_data.to_account_info();
        let acc_tdst = &ctx.accounts.token_dst.to_account_info();
        let acc_prog = &ctx.accounts.token_program.to_account_info();
        let acc_swap = &ctx.accounts.swap_data.to_account_info();
        let acc_tokn = &ctx.accounts.swap_token.to_account_info();
        let acc_inb = &ctx.accounts.inb_mint.to_account_info();
        let acc_out = &ctx.accounts.out_mint.to_account_info();
        
        let admin_role = has_role(&acc_auth, Role::SwapWithdraw, acc_admn.key);
        if admin_role.is_err() {
            msg!("No swap withdraw role");
            return Err(ErrorCode::AccessDenied.into());
        }

        // Verify withdrawal permit
        let permit_role = has_role(&acc_auth, Role::SwapPermit, acc_tdst.key);
        if permit_role.is_err() {
            msg!("No swap permit role");
            return Err(ErrorCode::AccessDenied.into());
        }

        // Verify swap associated token
        let acc_mint;
        if inp_inbound_token {
            acc_mint = ctx.accounts.inb_mint.to_account_info();
        } else {
            acc_mint = ctx.accounts.out_mint.to_account_info();
        }
        let derived_key = Pubkey::create_program_address(
            &[&ctx.accounts.swap_data.to_account_info().key.to_bytes(), &Token::id().to_bytes(), &acc_mint.key.to_bytes(), &[inp_tokn_nonce]],
            &AssociatedToken::id(),
        ).map_err(|_| ErrorCode::InvalidDerivedAccount)?;
        verify_matching_accounts(acc_tokn.key, &derived_key, Some(String::from("Invalid swap token vault")))?;

        msg!("Atellix: Attempt withdraw: {}", inp_amount.to_string());
        let swap_seeds = &[
            ctx.accounts.inb_mint.to_account_info().key.as_ref(),
            ctx.accounts.out_mint.to_account_info().key.as_ref(),
            &[inp_swpd_nonce],
        ];
        let swap_signer = &[&swap_seeds[..]];
        let cpi_accounts = Transfer {
            from: acc_tokn.clone(),
            to: acc_tdst.clone(),
            authority: ctx.accounts.swap_data.to_account_info(),
        };
        let cpi_program = acc_prog.clone();
        let cpi_ctx = CpiContext::new_with_signer(cpi_program, cpi_accounts, swap_signer);
        token::transfer(cpi_ctx, inp_amount)?;

        let clock = Clock::get()?;
        let sw = &mut ctx.accounts.swap_data;
        verify_matching_accounts(acc_inb.key, &sw.inb_mint, Some(String::from("Invalid inbound mint")))?;
        verify_matching_accounts(acc_out.key, &sw.out_mint, Some(String::from("Invalid outbound mint")))?;

        let new_total;
        if inp_inbound_token { 
            let mut ti = sw.inb_token_data;
            ti.amount = ti.amount.checked_sub(inp_amount).ok_or(ProgramError::from(ErrorCode::Overflow))?;
            sw.inb_token_data = ti;
            new_total = ti.amount;
        } else {
            let mut ti = sw.out_token_data;
            ti.amount = ti.amount.checked_sub(inp_amount).ok_or(ProgramError::from(ErrorCode::Overflow))?;
            sw.out_token_data = ti;
            new_total = ti.amount;
        }
        sw.slot = clock.slot;

        msg!("atellix-log");
        emit!(TransferEvent {
            event_hash: 107672350896016821143127613886765419987, // solana/program/atx-swap-contract/withdraw
            slot: clock.slot,
            user: acc_admn.key(),
            inbound_token: inp_inbound_token,
            swap_data: acc_swap.key(),
            token_acct: acc_tdst.key(),
            deposit: false,
            transfer: true,
            amount: inp_amount,
            new_total: new_total,
        });

        Ok(())
    }

    pub fn swap<'info>(ctx: Context<'_, '_, '_, 'info, Swap<'info>>,
        inp_swpd_nonce: u8,         // SwapData nonce
        inp_inb_nonce: u8,          // Associated token nonce for inb_token_dst
        inp_out_nonce: u8,          // Associated token nonce for out_token_src
        inp_root_nonce: u8,         // RootData nonce (merchant only)
        inp_swap_direction: bool,   // true = "Mint": Inbound -> Outbound ; false = "Burn": Outbound -> Inbound
        inp_merchant: bool,         // Merchant swap
        inp_is_buy: bool,           // Is "Buy" order, otherwise its a "Sell" order
                                    // Buy orders receive X out tokens, Sell orders send X inb tokens
        inp_tokens: u64,            // Number of tokens to send/receive (X tokens)
    ) -> ProgramResult {

        // Verify swap token info and fees token
        let acc_fee = &ctx.accounts.fees_token.to_account_info();
        let sw = &ctx.accounts.swap_data;
        if !sw.active {
            msg!("Inactive swap");
            return Err(ErrorCode::AccessDenied.into());
        }
        verify_matching_accounts(&sw.fees_token, acc_fee.key, Some(String::from("Invalid fees token")))?;

        let acc_inb_token_src = ctx.accounts.inb_token_src.to_account_info();
        let acc_inb_token_dst = ctx.accounts.inb_token_dst.to_account_info();
        let acc_out_token_src = ctx.accounts.out_token_src.to_account_info();
        let acc_out_token_dst = ctx.accounts.out_token_dst.to_account_info();

        // Verify inbound dest associated token
        let inb_data: &TokenData = &sw.inb_token_data;
        let out_data: &TokenData = &sw.out_token_data;

        let src_mint: &Pubkey;
        let dst_mint: &Pubkey;
        let current_data: &TokenData;
        if inp_swap_direction {
            src_mint = &sw.inb_mint;
            dst_mint = &sw.out_mint;
            current_data = inb_data;
        } else {
            src_mint = &sw.out_mint;
            dst_mint = &sw.inb_mint;
            current_data = out_data;
        }
        let derived_key_in = Pubkey::create_program_address(
            &[&ctx.accounts.swap_data.to_account_info().key.to_bytes(), &Token::id().to_bytes(), &src_mint.to_bytes(), &[inp_inb_nonce]],
            &AssociatedToken::id(),
        ).map_err(|_| {
            msg!("Invalid inbound token destination account nonce");
            ErrorCode::InvalidDerivedAccount
        })?;
        if derived_key_in != *acc_inb_token_dst.key {
            msg!("Invalid inbound token destination account");
            return Err(ErrorCode::InvalidDerivedAccount.into());
        }

        // Verify outbound src associated token
        let derived_key_out = Pubkey::create_program_address(
            &[&ctx.accounts.swap_data.to_account_info().key.to_bytes(), &Token::id().to_bytes(), &dst_mint.to_bytes(), &[inp_out_nonce]],
            &AssociatedToken::id(),
        ).map_err(|_| {
            msg!("Invalid outbound token source account nonce");
            ErrorCode::InvalidDerivedAccount
        })?;
        if derived_key_out != *acc_out_token_src.key {
            msg!("Invalid outbound token source account");
            return Err(ErrorCode::InvalidDerivedAccount.into());
        }

        // Verify merchant approval for merchant swaps
        let mut merchant_revenue: u64 = 0;
        let mut merchant_offset: usize = 0;
        let mut merchant_tx_id: u64 = 0;
        if inp_merchant {
            msg!("Merchant Swap");
            if current_data.oracle_rates || sw.oracle_verify {
                merchant_offset = 1;
            }
            let acc_auth = ctx.remaining_accounts.get(merchant_offset).unwrap();
            let acc_mrch_approval = ctx.remaining_accounts.get(merchant_offset + 2).unwrap();
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
                &[mrch_approval.merchant_key.as_ref(), Token::id().as_ref(), mrch_approval.token_mint.as_ref()],
                &AssociatedToken::id(),
            );
            verify_matching_accounts(acc_inb_token_src.key, &mrch_token, Some(String::from("Invalid merchant associated token")))?;
            merchant_revenue = mrch_approval.revenue;
            //msg!("Atellix: Merchant Revenue: {}", merchant_revenue.to_string());
        }

        let mut oracle_val: f64 = 0.0;
        let mut oracle_log_inuse: bool = false;
        let mut oracle_log_val: u128 = 0;
        let mut extra_decimals: u128 = 0;
        let adjust_i: i32 = 8;
        let base_f: f64 = 10.0;
        if current_data.oracle_rates || sw.oracle_verify {
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
        let mut swap_rate: u128 = current_data.rate_swap as u128;
        let mut base_rate: u128 = current_data.rate_base as u128;
        calculate_rates(current_data, sw, &mut swap_rate, &mut base_rate, &mut extra_decimals, oracle_log_val)?;
        //msg!("Atellix: Rates - Swap: {} Base: {}", swap_rate.to_string(), base_rate.to_string());
        let input_val: u128 = inp_tokens as u128;
        let result: u128 = calculate_swap(current_data, inp_is_buy, input_val, swap_rate, base_rate, extra_decimals, inp_merchant)?;
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

        let inbound_fees = (sw.fees_inbound && inp_swap_direction) || (!sw.fees_inbound && !inp_swap_direction);
        let tokens_fee: u64 = calculate_fee(current_data, inbound_fees, inp_is_buy, input_val, swap_rate, base_rate, extra_decimals, inp_merchant)?;

        /*msg!("Atellix: Inb: {} Out: {}", tokens_inb.to_string(), tokens_out.to_string());
        if inbound_fees {
            msg!("Atellix: Fee Inb: {}", tokens_fee.to_string());
        } else {
            msg!("Atellix: Fee Out: {}", tokens_fee.to_string());
        }*/

        if inp_merchant {
            if tokens_inb > merchant_revenue {
                msg!("Inbound token exceeds merchant balance");
                return Err(ErrorCode::Overflow.into());
            }

            // Record merchant revenue
            let root_seeds = &[ctx.program_id.as_ref(), &[inp_root_nonce]];
            let root_signer = &[&root_seeds[..]];
            let na_program = ctx.remaining_accounts.get(merchant_offset).unwrap(); // NetAuthority Program
            let na_accounts = RecordRevenue {
                revenue_admin: ctx.remaining_accounts.get(merchant_offset + 1).unwrap().clone(), // NetAuthority Root Data
                merchant_approval: ctx.remaining_accounts.get(merchant_offset + 2).unwrap().clone(),
            };
            let na_ctx = CpiContext::new_with_signer(na_program.clone(), na_accounts, root_signer);
 
            //msg!("Atellix: Attempt to record revenue withdrawal");
            net_authority::cpi::record_revenue(na_ctx, false, tokens_inb)?;

            // Reload data after CPI call
            let acc_mrch_approval = ctx.remaining_accounts.get(merchant_offset + 2).unwrap();
            let mut aprv_data: &[u8] = &acc_mrch_approval.try_borrow_data()?;
            let mrch_approval = MerchantApproval::try_deserialize(&mut aprv_data)?;
            merchant_tx_id = mrch_approval.tx_count;
        }

        //msg!("Atellix: Available Outbound Tokens: {}", out_info.amount.to_string());
        //msg!("Atellix: New Inbound Amount: {}", inb_info.amount.to_string());
        //msg!("Atellix: New Outbound Amount: {}", out_info.amount.to_string());

        let swap_seeds = &[
            sw.inb_mint.as_ref(),
            sw.out_mint.as_ref(),
            &[inp_swpd_nonce],
        ];
        let swap_signer = &[&swap_seeds[..]];

        let in_accounts = Transfer {
            from: acc_inb_token_src,
            to: acc_inb_token_dst,
            authority: ctx.accounts.swap_user.to_account_info(),
        };
        let cpi_prog1 = ctx.accounts.token_program.to_account_info();
        let in_ctx = CpiContext::new(cpi_prog1, in_accounts);
        //msg!("Atellix: Attempt Inbound Transfer");
        token::transfer(in_ctx, tokens_inb)?;

        let out_accounts = Transfer {
            from: acc_out_token_src,
            to: acc_out_token_dst,
            authority: ctx.accounts.swap_data.to_account_info(),
        };
        let cpi_prog2 = ctx.accounts.token_program.to_account_info();
        let out_ctx = CpiContext::new_with_signer(cpi_prog2, out_accounts, swap_signer);
        //msg!("Atellix: Attempt Outbound Transfer");
        token::transfer(out_ctx, tokens_out)?;

        if tokens_fee > 0 {
            if inbound_fees {
                let fees_accounts = Transfer {
                    from: ctx.accounts.inb_token_dst.to_account_info(),
                    to: ctx.accounts.fees_token.to_account_info(),
                    authority: ctx.accounts.swap_data.to_account_info(),
                };
                let cpi_prog = ctx.accounts.token_program.to_account_info();
                let fees_ctx = CpiContext::new_with_signer(cpi_prog, fees_accounts, swap_signer);
                //msg!("Atellix: Attempt Fees Transfer - Inbound Token");
                token::transfer(fees_ctx, tokens_fee)?;
            } else {
                let fees_accounts = Transfer {
                    from: ctx.accounts.out_token_src.to_account_info(),
                    to: ctx.accounts.fees_token.to_account_info(),
                    authority: ctx.accounts.swap_data.to_account_info(),
                };
                let cpi_prog = ctx.accounts.token_program.to_account_info();
                let fees_ctx = CpiContext::new_with_signer(cpi_prog, fees_accounts, swap_signer);
                //msg!("Atellix: Attempt Fees Transfer - Outbound Token");
                token::transfer(fees_ctx, tokens_fee)?;
            }
        }

        let clock = Clock::get()?;
        msg!("atellix-log");
        emit!(SwapEvent {
            event_hash: 144834217477609949185867766428666600068, // "solana/program/atx-swap-contract/swap" (MurmurHash3 128-bit unsigned)
            slot: clock.slot,
            swap_data: ctx.accounts.swap_data.key(),
            swap_direction: inp_swap_direction,
            user: ctx.accounts.swap_user.key(),
            inb_tokens: tokens_inb,
            inb_token_src: ctx.accounts.inb_token_src.key(),
            out_tokens: tokens_out,
            out_token_dst: ctx.accounts.out_token_dst.key(),
            fees_inbound: sw.fees_inbound,
            fees_amount: tokens_fee,
            fees_token: sw.fees_token,
            use_oracle: oracle_log_inuse,
            oracle_val: oracle_log_val,
            swap_tx: sw.swap_tx_count.checked_add(1).ok_or(ProgramError::from(ErrorCode::Overflow))?,
            merchant_tx_id: merchant_tx_id,
        });

        update_swap_result(ctx, inp_swap_direction, tokens_inb, tokens_out, tokens_fee, clock.slot)?;

        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, seeds = [program_id.as_ref()], bump, payer = program_admin)]
    pub root_data: Account<'info, RootData>,
    #[account(zero)]
    pub auth_data: UncheckedAccount<'info>,
    #[account(constraint = program.programdata_address() == Some(program_data.key()))]
    pub program: Program<'info, SwapContract>,
    #[account(constraint = program_data.upgrade_authority_address == Some(program_admin.key()))]
    pub program_data: Account<'info, ProgramData>,
    #[account(mut)]
    pub program_admin: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateMetadata<'info> {
    #[account(constraint = program.programdata_address() == Some(program_data.key()))]
    pub program: Program<'info, SwapContract>,
    #[account(constraint = program_data.upgrade_authority_address == Some(program_admin.key()))]
    pub program_data: Account<'info, ProgramData>,
    #[account(mut)]
    pub program_admin: Signer<'info>,
    #[account(init_if_needed, seeds = [program_id.as_ref(), b"metadata"], bump, payer = program_admin, space = 584)]
    pub program_info: Account<'info, ProgramMetadata>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(_inp_root_nonce: u8)]
pub struct UpdateRBAC<'info> {
    #[account(seeds = [program_id.as_ref()], bump = _inp_root_nonce)]
    pub root_data: Account<'info, RootData>,
    #[account(mut, constraint = root_data.root_authority == auth_data.key())]
    pub auth_data: UncheckedAccount<'info>,
    #[account(constraint = program.programdata_address() == Some(program_data.key()))]
    pub program: Program<'info, SwapContract>,
    pub program_data: Account<'info, ProgramData>,
    #[account(mut)]
    pub program_admin: Signer<'info>,
    pub rbac_user: AccountInfo<'info>,
}

#[derive(Accounts)]
#[instruction(inb_root_nonce: u8)]
pub struct CreateSwap<'info> {
    #[account(seeds = [program_id.as_ref()], bump = inb_root_nonce)]
    pub root_data: Account<'info, RootData>,
    #[account(constraint = root_data.root_authority == auth_data.key())]
    pub auth_data: UncheckedAccount<'info>,
    #[account(mut)]
    pub swap_admin: Signer<'info>,
    #[account(init, seeds = [inb_mint.key().as_ref(), out_mint.key().as_ref()], bump, payer = swap_admin)]
    pub swap_data: Account<'info, SwapData>,
    pub inb_mint: Account<'info, Mint>,
    pub out_mint: Account<'info, Mint>,
    pub fees_token: Account<'info, TokenAccount>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(_inp_root_nonce: u8, _inp_swpd_nonce: u8)]
pub struct UpdateSwap<'info> {
    #[account(seeds = [program_id.as_ref()], bump = _inp_root_nonce)]
    pub root_data: Account<'info, RootData>,
    #[account(constraint = root_data.root_authority == auth_data.key())]
    pub auth_data: UncheckedAccount<'info>,
    #[account(mut, seeds = [inb_mint.key().as_ref(), out_mint.key().as_ref()], bump = _inp_swpd_nonce)]
    pub swap_data: Account<'info, SwapData>,
    pub swap_admin: Signer<'info>,
    pub inb_mint: UncheckedAccount<'info>,
    pub out_mint: UncheckedAccount<'info>,
}

#[derive(Accounts)]
#[instruction(_inp_root_nonce: u8, _inp_swpd_nonce: u8)]
pub struct MintDeposit<'info> {
    #[account(seeds = [program_id.as_ref()], bump = _inp_root_nonce)]
    pub root_data: Account<'info, RootData>,
    #[account(constraint = root_data.root_authority == auth_data.key())]
    pub auth_data: UncheckedAccount<'info>,
    #[account(mut)]
    pub swap_token: Account<'info, TokenAccount>,
    pub swap_admin: Signer<'info>,
    #[account(mut)]
    pub inb_mint: UncheckedAccount<'info>,
    #[account(mut)]
    pub out_mint: UncheckedAccount<'info>,
    #[account(mut, seeds = [inb_mint.key().as_ref(), out_mint.key().as_ref()], bump = _inp_swpd_nonce)]
    pub swap_data: Account<'info, SwapData>,
    pub token_admin: Signer<'info>,
    #[account(address = token::ID)]
    pub token_program: AccountInfo<'info>,
}

#[derive(Accounts)]
#[instruction(_inp_root_nonce: u8, _inp_swpd_nonce: u8)]
pub struct TransferDeposit<'info> {
    #[account(seeds = [program_id.as_ref()], bump = _inp_root_nonce)]
    pub root_data: Account<'info, RootData>,
    #[account(constraint = root_data.root_authority == auth_data.key())]
    pub auth_data: UncheckedAccount<'info>,
    #[account(mut)]
    pub swap_token: Account<'info, TokenAccount>,
    pub swap_admin: Signer<'info>,
    pub inb_mint: UncheckedAccount<'info>,
    pub out_mint: UncheckedAccount<'info>,
    #[account(mut, seeds = [inb_mint.key().as_ref(), out_mint.key().as_ref()], bump = _inp_swpd_nonce)]
    pub swap_data: Account<'info, SwapData>,
    #[account(mut)]
    pub token_src: Account<'info, TokenAccount>,
    pub token_admin: Signer<'info>,
    #[account(address = token::ID)]
    pub token_program: AccountInfo<'info>,
}

#[derive(Accounts)]
#[instruction(_inp_root_nonce: u8, inp_swpd_nonce: u8)]
pub struct Withdraw<'info> {
    #[account(seeds = [program_id.as_ref()], bump = _inp_root_nonce)]
    pub root_data: Account<'info, RootData>,
    #[account(constraint = root_data.root_authority == auth_data.key())]
    pub auth_data: UncheckedAccount<'info>,
    #[account(mut)]
    pub swap_token: Account<'info, TokenAccount>,
    #[account(mut, seeds = [inb_mint.key().as_ref(), out_mint.key().as_ref()], bump = inp_swpd_nonce)]
    pub swap_data: Account<'info, SwapData>,
    pub swap_admin: Signer<'info>,
    pub inb_mint: UncheckedAccount<'info>,
    pub out_mint: UncheckedAccount<'info>,
    #[account(mut)]
    pub token_dst: Account<'info, TokenAccount>,
    #[account(address = token::ID)]
    pub token_program: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct Swap<'info> {
    #[account(mut)]
    pub swap_data: Account<'info, SwapData>,
    pub swap_user: Signer<'info>,
    #[account(mut)]
    pub inb_token_src: UncheckedAccount<'info>,
    #[account(mut)]
    pub inb_token_dst: UncheckedAccount<'info>,
    #[account(mut)]
    pub out_token_src: UncheckedAccount<'info>,
    #[account(mut)]
    pub out_token_dst: UncheckedAccount<'info>,
    #[account(mut)]
    pub fees_token: UncheckedAccount<'info>,
    #[account(address = token::ID)]
    pub token_program: UncheckedAccount<'info>,
}

#[derive(Default, Copy, Clone, AnchorDeserialize, AnchorSerialize)]
pub struct TokenData {
    pub basis_rates: bool,              // Uses cost-basis rates
    pub oracle_rates: bool,             // Uses oracle data for swap rates
    pub oracle_max: bool,               // Uses oracle data if greater
    pub oracle_inverse: bool,           // Inverse the oracle rate
    pub fees_bps: u32,                  // Swap fees in basis points
    pub fees_total: u64,                // All swap fees charged
    pub rate_swap: u64,                 // Swap rate
    pub rate_base: u64,                 // Base rate
    pub amount: u64,                    // Number of tokens in vault for this swap
    pub decimals: u8,                   // Mint decimal places
}
unsafe impl Pod for TokenData {}
unsafe impl Zeroable for TokenData {}

#[account]
#[derive(Default)]
pub struct SwapData {
    pub active: bool,                   // Active flag
    pub locked: bool,                   // Locked flag (prevents updates)
    pub slot: u64,                      // Last slot updated
    pub oracle_data: Pubkey,            // Oracle data address or Pubkey::default() for none
    pub oracle_type: u8,                // Oracle data type
    pub oracle_verify: bool,            // Uses oracle data to check for a valid range
    pub oracle_verify_min: u64,         // Valid range minimum (times 10**6, or 6 decimals)
    pub oracle_verify_max: u64,         // Valid range maximum (times 10**6, or 6 decimals)
    pub inb_mint: Pubkey,               // Token info for inbound tokens
    pub inb_token_data: TokenData,
    pub out_mint: Pubkey,               // Token info for outbound tokens
    pub out_token_data: TokenData,
    pub fees_inbound: bool,             // Use inbound (or alternatively outbound) token for fees
    pub fees_token: Pubkey,             // Fees account
    pub swap_tx_count: u64,             // Transaction index count
    pub tokens_outstanding: i128,
    pub tokens_offset: i128,
    pub cost_basis: i128,
    pub cost_offset: i128,
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
    pub swap_direction: bool,
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
    pub swap_tx: u64,
    pub merchant_tx_id: u64,
}

#[event]
pub struct TransferEvent {
    pub event_hash: u128,
    pub slot: u64,
    pub user: Pubkey,
    pub inbound_token: bool, 
    pub swap_data: Pubkey,
    pub token_acct: Pubkey, // The source or destination associated token (or default for mint)
    pub deposit: bool, // or, withdraw
    pub transfer: bool, // or, mint
    pub amount: u64,
    pub new_total: u64,
}

#[account]
#[derive(Default)]
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

