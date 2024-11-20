use std::sync::Arc;

#[macro_use]
extern crate log;

use base64::{engine::general_purpose::STANDARD as engine, Engine as _};
use ctclient::{CTClient, SthResult};
use ecdsa::VerifyingKey;
use elliptic_curve::PublicKey;
use keystore_rs::{KeyChain, KeyStore, KeyStoreType};
use p256::pkcs8::DecodePublicKey;
use p256::NistP256;
use prism_common::{
    hashchain::Hashchain,
    keys::SigningKey,
    operation::{Operation, ServiceChallenge, SignatureBundle},
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
        key: signing_key.clone(),
        start_height: 1,
    };

    let xenon2024 = LogInfo {
            id: "Xenon2024".to_string(),
            url: "https://ct.googleapis.com/logs/eu1/xenon2024/".to_string(),
            public_key: engine.decode("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEuWDgNB415GUAk0+QCb1a7ETdjA/O7RE+KllGmjG2x5n33O89zY+GwjWlPtwpurvyVOKoDIMIUQbeIW02UI44TQ==").unwrap()
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
    let register_service_op = Operation::new_register_service(
        "ct-service".to_string(),
        ServiceChallenge::from(sk.clone()),
    );

    let account_op = Operation::new_create_account(
        "xenon2024".to_string(),
        &sk.clone(),
        "ct-service".to_string(),
        &sk.clone(),
    )
    .unwrap();
    let mut account_hc = Hashchain::from_operation(account_op.clone()).unwrap();

    prover
        .clone()
        .validate_and_queue_update(&register_service_op)
        .await
        .unwrap();

    prover
        .clone()
        .validate_and_queue_update(&account_op)
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_secs(10));

    let log_prover = prover.clone();
    let xenon_key = signing_key.clone();
    let log_handle = spawn(async move {
        match watch_log(
            xenon2024,
            log_prover,
            SigningKey::Ed25519(Box::new(xenon_key)),
            &mut account_hc,
        )
        .await
        {
            Ok(_) => {
                println!("Log watching task completed");
            }
            Err(e) => {
                println!("Log watching task failed: {}", e);
            }
        }
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

async fn watch_log(
    log: LogInfo,
    prover: Arc<Prover>,
    key: SigningKey,
    hashchain: &mut Hashchain,
) -> Result<(), String> {
    let base64_string = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEuWDgNB415GUAk0+QCb1a7ETdjA/O7RE+KllGmjG2x5n33O89zY+GwjWlPtwpurvyVOKoDIMIUQbeIW02UI44TQ==";
    let bytes = engine.decode(base64_string).unwrap();
    let pk: VerifyingKey<NistP256> = VerifyingKey::from_public_key_der(bytes.as_slice()).unwrap();
    let verifying_key = prism_common::keys::VerifyingKey::Secp256r1(pk);

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
                    let update = hashchain
                        .add_data(
                            head.get_body(),
                            Some(SignatureBundle {
                                verifying_key: verifying_key.clone(),
                                signature: head.signature.as_slice()[4..].to_vec(),
                            }),
                            &key,
                            0,
                        )
                        .unwrap();
                    loop {
                        match prover.clone().validate_and_queue_update(&update).await {
                            Ok(_) => {
                                debug!("{}: {}", log.id, engine.encode(head.root_hash));
                                break;
                            }
                            Err(e) => {
                                error!("Error posting to prism {}: {}", log.url, e);
                                tokio::time::sleep(Duration::from_secs(1)).await;
                            }
                        };
                    }
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

#[cfg(test)]
mod tests {
    use ctclient::SignedTreeHead;
    use ecdsa::VerifyingKey;
    use openssl::pkey::PKey;
    use p256::pkcs8::DecodePublicKey;
    use p256::NistP256;

    use super::*;
    #[test]
    fn test_xenon_key_to_p256() {
        let base64_string = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEuWDgNB415GUAk0+QCb1a7ETdjA/O7RE+KllGmjG2x5n33O89zY+GwjWlPtwpurvyVOKoDIMIUQbeIW02UI44TQ==";
        let bytes = engine.decode(base64_string).unwrap();

        // for ctclient
        let evp_pkey = PKey::public_key_from_der(bytes.as_slice()).unwrap();

        // for prism
        let pk: VerifyingKey<NistP256> =
            VerifyingKey::from_public_key_der(bytes.as_slice()).unwrap();
        let verifying_key = prism_common::keys::VerifyingKey::Secp256r1(pk);

        let sth_b64 = "eyJ0cmVlX3NpemUiOjI2ODAzMDcwMjksInRpbWVzdGFtcCI6MTcyOTg0NDQ2Nzc5Niwic2hhMjU2X3Jvb3RfaGFzaCI6ImJiVFkvelRyRWVLZVMzbEMwREh3d0VLUFJZeDdBcVZYVksrMFFZWUllTUk9IiwidHJlZV9oZWFkX3NpZ25hdHVyZSI6IkJBTUFSakJFQWlCbUZvM3hkRC9wUjU5OGE2N1VmdjZteXJRZ3JZYkNBd0FCdTZDZ2ppZENUQUlnWWxxNXM3Z0NaclBoNUY5c1R6TWdNNFUxMTdtQ3ZOVW9Zdi9mbnZ3Wnlhcz0ifQ==";
        let bytes = String::from_utf8(engine.decode(sth_b64).unwrap()).unwrap();
        let sth = SignedTreeHead::from_json(&bytes).unwrap();
        let message = sth.get_body();

        ecdsa::der::Signature::<NistP256>::try_from(&sth.signature.as_slice()[4..]).unwrap();

        sth.verify(&evp_pkey).unwrap();

        verifying_key
            .verify_signature(message.as_slice(), &sth.signature.as_slice()[4..])
            .unwrap();
    }
}
