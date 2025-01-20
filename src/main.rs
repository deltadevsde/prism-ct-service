mod log_list;
mod log_monitoring;

use anyhow::{anyhow, Result};
use keystore_rs::{KeyChain, KeyStore};
use log::debug;
use log_monitoring::monitor_operators;
use prism_da::{memory::InMemoryDataAvailabilityLayer, DataAvailabilityLayer};
use prism_keys::SigningKey;
use prism_storage::inmemory::InMemoryDatabase;
use std::{sync::Arc, time::Duration};
use tokio::spawn;

use prism_prover::{webserver::WebServerConfig, Config, Prover};

pub static CT_SERVICE_KEY_ID: &str = "ct_service";

#[tokio::main]
async fn main() -> Result<()> {
    std::env::set_var(
            "RUST_LOG",
            "DEBUG,ctclient::internal=off,reqwest=off,hyper=off,tracing=off,sp1_stark=info,jmt=off,p3_dft=off,p3_fri=off,sp1_core_executor=info,sp1_recursion_program=info,p3_merkle_tree=off,sp1_recursion_compiler=off,sp1_core_machine=off",
        );
    pretty_env_logger::init();

    let db = InMemoryDatabase::new();
    let (da_layer, _, _) = InMemoryDataAvailabilityLayer::new(5);

    let keystore_sk = KeyChain
        .get_signing_key(CT_SERVICE_KEY_ID)
        .map_err(|e| anyhow!("Error getting key from store: {}", e))?;

    let sk = SigningKey::Ed25519(Box::new(keystore_sk.clone()));

    let cfg = Config {
        prover: true,
        batcher: true,
        webserver: WebServerConfig {
            enabled: true,
            host: "127.0.0.1".to_string(),
            port: 50524,
        },
        signing_key: sk.clone(),
        verifying_key: sk.verifying_key(),
        start_height: 1,
    };

    let prover = Arc::new(
        Prover::new(
            Arc::new(Box::new(db)),
            Arc::new(da_layer) as Arc<dyn DataAvailabilityLayer>,
            &cfg,
        )
        .unwrap(),
    );

    let runner = prover.clone();
    let runner_handle = spawn(async move {
        debug!("starting prover");
        if let Err(e) = runner.run().await {
            log::error!("Error occurred while running prover: {:?}", e);
        }
    });

    let operators = vec![
        "Google".to_string(),
        "Cloudflare".to_string(),
        "DigiCert".to_string(),
        "Sectigo".to_string(),
        "Let's Encrypt".to_string(),
    ];
    let interval = Duration::from_secs(60);

    monitor_operators(operators, interval, sk, prover).await?;

    tokio::select! {
        _ = runner_handle => {
            println!("Prover runner task completed");
        }
    }

    Ok(())
}
