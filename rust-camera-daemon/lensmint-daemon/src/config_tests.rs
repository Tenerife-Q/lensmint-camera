use super::*;

#[test]
fn embedded_contracts_include_sepolia_mint_contract() {
    let config: ContractsConfig =
        serde_json::from_str(EMBEDDED_CONTRACTS).expect("parse embedded contracts");
    let sepolia = config.evm(11_155_111).expect("Sepolia config");

    assert_eq!(sepolia.name, "Sepolia");
    assert_eq!(
        sepolia.lensmint,
        "0x263E52714bb8A80C98d08A7fC541e9Ae1d6C96cC"
    );
}

#[test]
fn embedded_contracts_include_solana_devnet_programs() {
    let config: ContractsConfig =
        serde_json::from_str(EMBEDDED_CONTRACTS).expect("parse embedded contracts");
    let devnet = config.solana("devnet").expect("Solana devnet config");

    assert_eq!(
        devnet.program_id,
        "Cco1bP778KAZNR5uLCRgmt3iFQ3cjGudyiMcnTJ7X1nW"
    );
    assert_eq!(
        devnet.mpl_core,
        "CoREENxT6tW1HoK8ypY1SxRMZTcVPm7R94rH4PZNhX7d"
    );
}

#[test]
fn embedded_solana_rpc_lists_cover_each_ui_cluster() {
    let config: SolanaRpcConfig =
        serde_json::from_str(EMBEDDED_SOLANA_RPCS).expect("parse embedded Solana RPCs");

    for cluster in ["devnet", "testnet", "mainnet"] {
        let urls = config
            .get(cluster)
            .unwrap_or_else(|| panic!("{cluster} RPC list"));
        assert!(!urls.is_empty(), "{cluster} RPC list must not be empty");
        assert!(
            urls.iter().all(|url| url.starts_with("https://")),
            "{cluster} RPCs must use HTTPS"
        );
    }
}
