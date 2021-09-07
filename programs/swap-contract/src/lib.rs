use anchor_lang::prelude::*;
use switchboard_program;
use switchboard_program::{
    AggregatorState,
    RoundResult,
    FastRoundResultAccountData,
    fast_parse_switchboard_result
};

extern crate decode_account;
use decode_account::parse_bpf_loader::{ parse_bpf_upgradeable_loader, BpfUpgradeableLoaderAccountType };

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
        msg!("Create root data account");
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
            active: true,
            net_auth: *ctx.accounts.net_auth.to_account_info().key,
        };
        let mut root_data = acc_root.try_borrow_mut_data()?;
        let root_dst: &mut [u8] = &mut root_data;
        let mut root_crs = Cursor::new(root_dst);
        ra.try_serialize(&mut root_crs)?;

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
    pub root_data: AccountInfo<'info>,
    pub net_auth: AccountInfo<'info>,
    pub program: AccountInfo<'info>,
    pub program_data: AccountInfo<'info>,
    #[account(signer)]
    pub program_admin: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct OracleResult<'info> {
    pub oracle_data: AccountInfo<'info>,
}

#[account]
pub struct RootData {
    pub active: bool,
    pub net_auth: Pubkey, // Network authority program to validate swap approval records
}

impl RootData {
    pub fn active(&self) -> bool {
        self.active
    }

    pub fn net_auth(&self) -> Pubkey {
        self.net_auth
    }
}

#[account]
pub struct SwapData {
    pub active: bool,                   // Active flag
    //pub merchant_only: bool,            // Merchant-only flag
    pub oracle_rates: bool,             // Uses oracle data for swap rates
    pub oracle_verify: bool,            // Uses oracle data to check for a valid range
    pub oracle_verify_min: f64,         // Valid range minimum
    pub oracle_verify_max: f64,         // Valid range maximum
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

