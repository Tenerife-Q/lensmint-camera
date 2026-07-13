use anchor_lang::prelude::*;

declare_id!("dsMM8ygdvsiG86vMhcfui95wzxGx8rSgc7xbJWSZHtn");

#[program]
pub mod solana_contracts {
    use super::*;

    pub fn mint_from_hardware(
        ctx: Context<MintHardware>,
        uuid: String,
        sha256_hash: [u8; 32],
        p_hash: String,
    ) -> Result<()> {
        let camera_record = &mut ctx.accounts.camera_record;
        
        camera_record.owner = *ctx.accounts.relayer.key;
        camera_record.uuid = uuid;
        camera_record.sha256_hash = sha256_hash;
        camera_record.p_hash = p_hash;
        camera_record.timestamp = Clock::get()?.unix_timestamp;

        msg!("LensMint Camera Record Minted!");
        msg!("UUID: {}", camera_record.uuid);
        
        Ok(())
    }
}

#[derive(Accounts)]
#[instruction(uuid: String, sha256_hash: [u8; 32], p_hash: String)]
pub struct MintHardware<'info> {
    #[account(
        init,
        payer = relayer,
        space = 8 + 32 + 40 + 32 + 68 + 8, 
        seeds = [b"camera", sha256_hash.as_ref()],
        bump
    )]
    pub camera_record: Account<'info, CameraRecord>,
    
    #[account(mut)]
    pub relayer: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[account]
pub struct CameraRecord {
    pub owner: Pubkey,
    pub uuid: String,
    pub sha256_hash: [u8; 32],
    pub p_hash: String,
    pub timestamp: i64,
}