use std::sync::Arc;

#[macro_use]
extern crate log;

use ctclient::{CTClient, SthResult};
use keystore_rs::{KeyChain, KeyStore, KeyStoreType};
use prism_common::{
    keys::SigningKey,
    operation::{Operation, ServiceChallenge},
};
use prism_da::{memory::InMemoryDataAvailabilityLayer, DataAvailabilityLayer};
use prism_prover::{webserver::WebServerConfig, Config, Prover};
use prism_storage::inmemory::InMemoryDatabase;
use std::time::Duration;
use tokio::spawn;

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct LogInfo {
    id: String,
    url: String,
    public_key: Vec<u8>,
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var(
        "RUST_LOG",
        "DEBUG,ctclient::internal=off,reqwest=off,hyper=off,tracing=off,sp1_stark=info,jmt=off,p3_dft=off,p3_fri=off,sp1_core_executor=info,sp1_recursion_program=info,p3_merkle_tree=off,sp1_recursion_compiler=off,sp1_core_machine=off",
    );
    pretty_env_logger::init();

    let db = InMemoryDatabase::new();
    let (da_layer, _, _) = InMemoryDataAvailabilityLayer::new(5);

    let signing_key = KeyStoreType::KeyChain(KeyChain)
        .get_signing_key()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    let cfg = Config {
        prover: true,
        batcher: true,
        webserver: WebServerConfig::default(),
        signing_key: signing_key.clone(),
        verifying_key: signing_key.verification_key(),
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
        runner.run().await;
    });

    let sk: SigningKey = SigningKey::Ed25519(Box::new(signing_key.clone()));
    let register_service_op =
        Operation::new_register_service("ct-service".to_string(), ServiceChallenge::from(sk));

    prover
        .validate_and_queue_update(&register_service_op)
        .await
        .unwrap();

    let xenon2024 = LogInfo {
        id: "Xenon2024".to_string(),
        url: "https://ct.googleapis.com/logs/us1/argon2024/".to_string(),
        public_key: base64::decode("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHblsqctplMVc5ramA7vSuNxUQxcomQwGAVAdnWTAWUYr3MgDHQW0LagJ95lB7QT75Ve6JgT2EVLOFGU7L3YrwA").unwrap()
    };

    let log_handle = spawn(async move {
        watch_log(xenon2024).await;
    });

    tokio::select! {
        _ = log_handle => {
            println!("Log watching task completed");
        }
        _ = runner_handle => {
            println!("Prover runner task completed");
        }
    }
    Ok(())
}

async fn watch_log(log: LogInfo) -> Result<(), String> {
    let mut client = match CTClient::new_from_latest_th(&log.url, &log.public_key) {
        Ok(client) => client,
        Err(e) => {
            return Err(format!(
                "Error initializing client for log {}: {}",
                log.url, e
            ));
        }
    };
    let mut last_tree_head = [0u8; 32];
    loop {
        // let update_result = client.update(Some(|certs: &[X509]| {}));
        let update_result = client.light_update();

        match update_result {
            SthResult::Ok(head) => {
                if !head.root_hash.eq(&last_tree_head) {
                    last_tree_head = head.root_hash;
                    debug!("{}: {}", log.id, base64::encode(head.root_hash));
                }
            }
            SthResult::Err(e) => {
                error!("Error in log {}: {}", log.url, e);
            }
            SthResult::ErrWithSth(e, head) => {
                error!("Error with sth in log {}: {}", log.url, e);

                if !head.root_hash.eq(&last_tree_head) {
                    last_tree_head = head.root_hash;
                    debug!("{}: {}", log.id, base64::encode(head.root_hash));
                }
            }
        }

        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}
