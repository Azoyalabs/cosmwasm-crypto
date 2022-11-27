use ed25519_zebra::{Signature, VerificationKey};

use crate::errors::{CryptoError, CryptoResult};

/// Length of a serialized public key
pub const EDDSA_PUBKEY_LEN: usize = 32;

/// EdDSA ed25519 implementation.
///
/// This function verifies messages against a signature, with the public key of the signer,
/// using the ed25519 elliptic curve digital signature parametrization / algorithm.
///
/// The maximum currently supported message length is 4096 bytes.
/// The signature and public key are in [Tendermint](https://docs.tendermint.com/v0.32/spec/blockchain/encoding.html#public-key-cryptography)
/// format:
/// - signature: raw ED25519 signature (64 bytes).
/// - public key: raw ED25519 public key (32 bytes).
pub fn ed25519_verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> CryptoResult<bool> {
    // Validation
    let signature = read_signature(signature)?;
    let pubkey = read_pubkey(public_key)?;

    // Verification
    match VerificationKey::try_from(pubkey)
        .and_then(|vk| vk.verify(&Signature::from(signature), message))
    {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}



/// Error raised when signature is not 64 bytes long
struct InvalidEd25519SignatureFormat;

impl From<InvalidEd25519SignatureFormat> for CryptoError {
    fn from(_original: InvalidEd25519SignatureFormat) -> Self {
        CryptoError::invalid_signature_format()
    }
}

fn read_signature(data: &[u8]) -> Result<[u8; 64], InvalidEd25519SignatureFormat> {
    data.try_into().map_err(|_| InvalidEd25519SignatureFormat)
}

/// Error raised when pubkey is not 32 bytes long
struct InvalidEd25519PubkeyFormat;

impl From<InvalidEd25519PubkeyFormat> for CryptoError {
    fn from(_original: InvalidEd25519PubkeyFormat) -> Self {
        CryptoError::invalid_pubkey_format()
    }
}

fn read_pubkey(data: &[u8]) -> Result<[u8; 32], InvalidEd25519PubkeyFormat> {
    data.try_into().map_err(|_| InvalidEd25519PubkeyFormat)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_zebra::SigningKey;
    use serde::Deserialize;
    use rand_core::OsRng;

    // For generic signature verification
    const MSG: &str = "Hello World!";

    // Cosmos ed25519 signature verification
    // TEST 1 from https://tools.ietf.org/html/rfc8032#section-7.1
    const COSMOS_ED25519_MSG: &str = "";
    const COSMOS_ED25519_PRIVATE_KEY_HEX: &str =
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const COSMOS_ED25519_PUBLIC_KEY_HEX: &str =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const COSMOS_ED25519_SIGNATURE_HEX: &str = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

    // Test data from https://tools.ietf.org/html/rfc8032#section-7.1
    const COSMOS_ED25519_TESTS_JSON: &str = "./testdata/ed25519_tests.json";

    #[derive(Deserialize, Debug)]
    struct Encoded {
        #[serde(rename = "privkey")]
        #[allow(dead_code)]
        private_key: String,
        #[serde(rename = "pubkey")]
        public_key: String,
        message: String,
        signature: String,
    }

    fn read_cosmos_sigs() -> Vec<Encoded> {
        use std::fs::File;
        use std::io::BufReader;

        // Open the file in read-only mode with buffer.
        let file = File::open(COSMOS_ED25519_TESTS_JSON).unwrap();
        let reader = BufReader::new(file);

        serde_json::from_reader(reader).unwrap()
    }

    #[test]
    fn test_ed25519_verify() {
        let message = MSG.as_bytes();
        // Signing
        let secret_key = SigningKey::new(OsRng);
        let signature = secret_key.sign(message);

        let public_key = VerificationKey::from(&secret_key);

        // Serialization. Types can be converted to raw byte arrays with From/Into
        let signature_bytes: [u8; 64] = signature.into();
        let public_key_bytes: [u8; 32] = public_key.into();

        // Verification
        assert!(ed25519_verify(message, &signature_bytes, &public_key_bytes).unwrap());

        // Wrong message fails
        let bad_message = [message, b"\0"].concat();
        assert!(!ed25519_verify(&bad_message, &signature_bytes, &public_key_bytes).unwrap());

        // Other pubkey fails
        let other_secret_key = SigningKey::new(OsRng);
        let other_public_key = VerificationKey::from(&other_secret_key);
        let other_public_key_bytes: [u8; 32] = other_public_key.into();
        assert!(!ed25519_verify(message, &signature_bytes, &other_public_key_bytes).unwrap());
    }

    #[test]
    fn test_cosmos_ed25519_verify() {
        let secret_key = SigningKey::try_from(
            hex::decode(COSMOS_ED25519_PRIVATE_KEY_HEX)
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let public_key = VerificationKey::try_from(
            hex::decode(COSMOS_ED25519_PUBLIC_KEY_HEX)
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let signature = secret_key.sign(COSMOS_ED25519_MSG.as_bytes());

        let signature_bytes: [u8; 64] = signature.into();
        let public_key_bytes: [u8; 32] = public_key.into();

        assert_eq!(
            signature_bytes,
            hex::decode(COSMOS_ED25519_SIGNATURE_HEX)
                .unwrap()
                .as_slice()
        );

        assert!(ed25519_verify(
            COSMOS_ED25519_MSG.as_bytes(),
            &signature_bytes,
            &public_key_bytes
        )
        .unwrap());
    }

    #[test]
    fn test_cosmos_extra_ed25519_verify() {
        let codes = read_cosmos_sigs();

        for (i, encoded) in (1..).zip(codes) {
            let message = hex::decode(&encoded.message).unwrap();

            let signature = hex::decode(&encoded.signature).unwrap();

            let public_key = hex::decode(&encoded.public_key).unwrap();

            // ed25519_verify() works
            assert!(
                ed25519_verify(&message, &signature, &public_key).unwrap(),
                "verify() failed (test case {})",
                i
            );
        }
    } 

}
