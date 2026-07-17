use ed25519_dalek::{pkcs8::DecodePrivateKey, pkcs8::EncodePrivateKey, Signature, Signer, SigningKey};
use rand::rngs::OsRng;
use std::fs::{self, OpenOptions};
use std::io::Write;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

pub struct LocalKeystore {
    pub signing_key: SigningKey,
}

impl LocalKeystore {
    /// Loads the Ed25519 keypair from the platform's standard data directory 
    /// (e.g., `~/.local/share/lensmint/keystore.pem` on Unix).
    ///
    /// If no identity exists, a new cryptographic pair is generated and securely 
    /// stored with strict Unix file permissions (0400).
    pub fn load_or_generate() -> Result<Self, Box<dyn std::error::Error>> {
        let proj_dirs = directories::ProjectDirs::from("", "", "lensmint")
            .ok_or("Could not resolve local App directories")?;
            
        let config_dir = proj_dirs.data_dir();

        if !config_dir.exists() {
            fs::create_dir_all(config_dir)?;
        }

        let key_path = config_dir.join("keystore.pem");

        let signing_key = if key_path.exists() {
            let pem_str = fs::read_to_string(&key_path)?;
            SigningKey::from_pkcs8_pem(&pem_str)?
        } else {
            let mut csprng = OsRng;
            let key = SigningKey::generate(&mut csprng);
            let pem_str = key.to_pkcs8_pem(Default::default())?;

            let mut options = OpenOptions::new();
            options.write(true).create_new(true);

            #[cfg(unix)]
            {
                options.mode(0o400);
            }

            let mut file = options.open(&key_path)?;
            file.write_all(pem_str.as_bytes())?;
            key
        };

        let keystore = Self { signing_key };
        
        println!("==================================================");
        println!("[LensMint] Camera Ed25519 Pubkey for EVM Contract:");
        println!("0x{}", keystore.public_key_hex());
        println!("==================================================");

        Ok(keystore)
    }

    /// Signs raw off-chain payload data using the local identity key.
    pub fn sign_payload(&self, payload: &[u8]) -> Signature {
        self.signing_key.sign(payload)
    }

    /// Returns the public key encoded as a hex string for Web3 JSON compatibility.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().as_bytes())
    }

    /// Signs the payload and returns the resulting signature encoded as a hex string.
    pub fn sign_payload_hex(&self, payload: &[u8]) -> String {
        let sig = self.sign_payload(payload);
        hex::encode(sig.to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    #[test]
    fn test_sign_and_verify_success() {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let keystore = LocalKeystore {
            signing_key: signing_key.clone(),
        };

        let mock_hash = b"0x21a4f00d23..."; 
        let signature = keystore.sign_payload(mock_hash);

        let verifying_key = signing_key.verifying_key();
        assert!(
            verifying_key.verify(mock_hash, &signature).is_ok(),
            "Signature payload mismatch with hardware identity."
        );
    }
    
    #[test]
    fn test_sign_and_verify_forged_failure() {
        let mut csprng = OsRng;
        let original_key = SigningKey::generate(&mut csprng);
        let keystore = LocalKeystore {
            signing_key: original_key,
        };
        
        let signature = keystore.sign_payload(b"Valid Data");
        
        let hacker_key = SigningKey::generate(&mut csprng);
        let hacker_pub = hacker_key.verifying_key();
        
        assert!(
            hacker_pub.verify(b"Valid Data", &signature).is_err(),
            "Forged payload authentication should fail!"
        );
    }
}