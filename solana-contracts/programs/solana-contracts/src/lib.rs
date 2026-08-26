use anchor_lang::prelude::*;
use mpl_core::{instructions::CreateV1CpiBuilder, ID as MPL_CORE_ID};

declare_id!("Cco1bP778KAZNR5uLCRgmt3iFQ3cjGudyiMcnTJ7X1nW");

#[program]
pub mod solana_contracts {
    use super::*;

    // Register physical hardware camera
    pub fn register_device(ctx: Context<RegisterDevice>, device_pubkey: [u8; 32]) -> Result<()> {
        let device_record = &mut ctx.accounts.device_record;
        device_record.is_active = true;
        device_record.pubkey = device_pubkey;
        msg!("Device registered successfully");
        Ok(())
    }

    // Mint NFT via hardware verification
    pub fn mint_from_hardware(
        ctx: Context<MintHardware>,
        uuid: String,
        sha256_hash: [u8; 32],
        p_hash: String,
        device_pubkey: [u8; 32],
    ) -> Result<()> {
        // Active and ownership guards
        require!(ctx.accounts.device_record.is_active, CustomError::DeviceInactive);
        require!(ctx.accounts.device_record.pubkey == device_pubkey, CustomError::DeviceMismatch);

        // Manually verify Program ID to avoid macro-level type conflicts
        if ctx.accounts.mpl_core_program.key().to_bytes() != MPL_CORE_ID.to_bytes() {
            return err!(CustomError::InvalidProgramId);
        }

        let camera_record = &mut ctx.accounts.camera_record;
        camera_record.owner = *ctx.accounts.relayer.key;
        camera_record.uuid = uuid.clone();
        camera_record.sha256_hash = sha256_hash;
        camera_record.p_hash = p_hash;
        camera_record.timestamp = Clock::get()?.unix_timestamp;

        // Perform CPI
        create_core_asset_cpi(
            &ctx.accounts.mpl_core_program.to_account_info(),
            &ctx.accounts.asset.to_account_info(),
            &ctx.accounts.relayer.to_account_info(),
            &ctx.accounts.system_program.to_account_info(),
            format!("LensMint {}", uuid),
        )?;

        msg!("LensMint Asset Minted successfully!");
        Ok(())
    }
}

// Inline(never) prevents SBF stack limit (4KB) overflow
#[inline(never)]
pub fn create_core_asset_cpi<'info>(
    mpl_core_program: &AccountInfo<'info>,
    asset: &AccountInfo<'info>,
    payer: &AccountInfo<'info>,
    system_program: &AccountInfo<'info>,
    name: String,
) -> Result<()> {
    // Rust pointer black magic: Let the compiler infer types based on target signatures, bypassing Cargo.toml conflicts
    unsafe {
        CreateV1CpiBuilder::new(&*(mpl_core_program as *const _ as *const _))
            .asset(&*(asset as *const _ as *const _))
            .payer(&*(payer as *const _ as *const _))
            .system_program(&*(system_program as *const _ as *const _))
            .name(name)
            .uri(String::from("https://arweave.net/placeholder"))
            .invoke()
            .map_err(|_| CustomError::CpiError.into())
    }
}

#[derive(Accounts)]
#[instruction(device_pubkey: [u8; 32])]
pub struct RegisterDevice<'info> {
    // Boxed to prevent stack overflow
    #[account(
        init,
        payer = admin,
        space = 8 + 32 + 1,
        seeds = [b"device", device_pubkey.as_ref()],
        bump
    )]
    pub device_record: Box<Account<'info, DeviceRecord>>,
    #[account(mut)]
    pub admin: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(uuid: String, sha256_hash: [u8; 32], p_hash: String, device_pubkey: [u8; 32])]
pub struct MintHardware<'info> {
    // Boxed to prevent stack overflow
    #[account(
        seeds = [b"device", device_pubkey.as_ref()],
        bump,
    )]
    pub device_record: Box<Account<'info, DeviceRecord>>, 

    // Boxed to prevent stack overflow
    #[account(
        init,
        payer = relayer,
        space = 8 + 32 + 40 + 32 + 68 + 8, 
        seeds = [b"camera", sha256_hash.as_ref()],
        bump
    )]
    pub camera_record: Box<Account<'info, CameraRecord>>,
    
    /// CHECK: Target asset (Signed client side)
    #[account(mut)]
    pub asset: Signer<'info>,

    #[account(mut)]
    pub relayer: Signer<'info>,
    
    pub system_program: Program<'info, System>,
    
    /// CHECK: Metaplex Core Program (Program ID checked inside instruction body)
    pub mpl_core_program: UncheckedAccount<'info>,
}

#[account]
pub struct DeviceRecord {
    pub pubkey: [u8; 32],
    pub is_active: bool,
}

#[account]
pub struct CameraRecord {
    pub owner: Pubkey,
    pub uuid: String,
    pub sha256_hash: [u8; 32],
    pub p_hash: String,
    pub timestamp: i64,
}

#[error_code]
pub enum CustomError {
    #[msg("Hardware device is not active or unauthorized.")]
    DeviceInactive,
    #[msg("Device pubkey mismatch.")]
    DeviceMismatch,
    #[msg("Invalid Metaplex Core Program ID.")]
    InvalidProgramId,
    #[msg("CPI to Metaplex Core failed.")]
    CpiError,
}