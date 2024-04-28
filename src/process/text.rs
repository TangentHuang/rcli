use crate::cli::{TextEncryptFormat, TextSignFormat};
use crate::process_gen_pass;
use crate::utils::get_reader;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::Nonce;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::fs;
use std::io::Read;
use std::path::Path;

pub trait TextSign {
    fn sign(&self, reader: &mut dyn Read) -> anyhow::Result<Vec<u8>>;
}
pub trait TextVerify {
    fn verify(&self, reader: impl Read, sig: &[u8]) -> anyhow::Result<bool>;
}

pub trait KeyGenerator {
    fn generate() -> anyhow::Result<Vec<Vec<u8>>>;
}
pub trait KeyLoader {
    fn load(path: impl AsRef<Path>) -> anyhow::Result<Self>
    where
        Self: Sized;
}

pub trait TextEncrypt {
    fn encrypt(&self, reader: impl Read) -> anyhow::Result<Vec<Vec<u8>>>;
}

pub trait TextDecrypt {
    fn decrypt(&self, reader: impl Read) -> anyhow::Result<Vec<u8>>;
}

pub struct Blake3 {
    key: [u8; 32],
}

pub struct Ed25519Signer {
    key: SigningKey,
}

pub struct Ed25519Verifier {
    key: VerifyingKey,
}

pub struct Chacha20Poly1305 {
    key: [u8; 32],
}

pub fn process_encrypt(
    input: &str,
    key: &str,
    format: TextEncryptFormat,
) -> anyhow::Result<String> {
    let ciphertext = match format {
        TextEncryptFormat::Chacha20Poly1305 => {
            let reader = get_reader(input)?;
            let encryptor = Chacha20Poly1305::load(key)?;
            let ciphertext_info = encryptor.encrypt(reader)?;

            //encode base64 : ciphertext: nonce
            let ciphertext = BASE64_URL_SAFE_NO_PAD.encode(&ciphertext_info[0]);
            let nonce = BASE64_URL_SAFE_NO_PAD.encode(&ciphertext_info[1]);
            format!("{}:{}", ciphertext, nonce)
        }
    };
    println!("{}", ciphertext);
    Ok(ciphertext)
}

pub fn process_decrypt(
    input: &str,
    key: &str,
    format: TextEncryptFormat,
) -> anyhow::Result<String> {
    let plaintext = match format {
        TextEncryptFormat::Chacha20Poly1305 => {
            let reader = get_reader(input)?;
            let decryptor = Chacha20Poly1305::load(key)?;
            let plaintext = decryptor.decrypt(reader)?;
            BASE64_URL_SAFE_NO_PAD.encode(plaintext)
        }
    };
    println!("plaintext encode by BASE64_URL_SAFE_NO_PAD:{}", plaintext);
    Ok(plaintext)
}

pub fn process_sign(input: &str, key: &str, format: TextSignFormat) -> anyhow::Result<String> {
    let mut reader = get_reader(input)?;
    let singed = match format {
        TextSignFormat::Blake3 => {
            let signer = Blake3::load(key)?;
            signer.sign(&mut reader)?
        }
        TextSignFormat::Ed25519 => {
            let signer = Ed25519Signer::load(key)?;
            signer.sign(&mut reader)?
        }
    };
    let singed = BASE64_URL_SAFE_NO_PAD.encode(singed);
    Ok(singed)
}

pub fn process_verify(
    input: &str,
    key: &str,
    sig: &str,
    format: TextSignFormat,
) -> anyhow::Result<bool> {
    let mut reader = get_reader(input)?;
    let sig = BASE64_URL_SAFE_NO_PAD.decode(sig)?;
    let is_verify = match format {
        TextSignFormat::Blake3 => {
            let verifier = Blake3::load(key)?;
            verifier.verify(&mut reader, &sig)?
        }
        TextSignFormat::Ed25519 => {
            let verifier = Ed25519Verifier::load(key)?;
            verifier.verify(&mut reader, &sig)?
        }
    };
    Ok(is_verify)
}

pub fn process_gen_key(format: TextSignFormat) -> anyhow::Result<Vec<Vec<u8>>> {
    let keys = match format {
        TextSignFormat::Blake3 => Blake3::generate()?,
        TextSignFormat::Ed25519 => Ed25519Signer::generate()?,
    };
    Ok(keys)
}

impl KeyGenerator for Blake3 {
    fn generate() -> anyhow::Result<Vec<Vec<u8>>> {
        let key = process_gen_pass(32, true, true, true, true)?;
        Ok(vec![key.as_bytes().to_vec()])
    }
}

impl KeyGenerator for Ed25519Signer {
    fn generate() -> anyhow::Result<Vec<Vec<u8>>> {
        let mut csprng = rand::rngs::OsRng;
        let sk = SigningKey::generate(&mut csprng);
        let pk = sk.verifying_key().to_bytes().to_vec();
        let sk = sk.to_bytes().to_vec();
        Ok(vec![sk, pk])
    }
}

impl TextSign for Blake3 {
    fn sign(&self, reader: &mut dyn Read) -> anyhow::Result<Vec<u8>> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).unwrap();
        Ok(blake3::keyed_hash(&self.key, &buf).as_bytes().to_vec())
    }
}

impl TextVerify for Blake3 {
    fn verify(&self, mut reader: impl Read, sig: &[u8]) -> anyhow::Result<bool> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let hash = blake3::keyed_hash(&self.key, &buf);
        let hash = hash.as_bytes();
        Ok(hash == sig)
    }
}

impl TextSign for Ed25519Signer {
    fn sign(&self, reader: &mut dyn Read) -> anyhow::Result<Vec<u8>> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let sig = self.key.sign(&buf);
        Ok(sig.to_bytes().to_vec())
    }
}
impl TextVerify for Ed25519Verifier {
    fn verify(&self, mut reader: impl Read, sig: &[u8]) -> anyhow::Result<bool> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let sig = Signature::from_bytes(sig.try_into()?);
        Ok(self.key.verify_strict(&buf, &sig).is_ok())
    }
}

impl KeyLoader for Blake3 {
    fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let key = fs::read(path)?;
        Self::try_new(&key)
    }
}

impl KeyLoader for Ed25519Signer {
    fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let key = fs::read(path)?;
        Self::try_new(&key)
    }
}

impl KeyLoader for Ed25519Verifier {
    fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let key = fs::read(path)?;
        Self::try_new(&key)
    }
}

impl KeyLoader for Chacha20Poly1305 {
    fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let key = fs::read(path)?;
        Self::try_new(&key)
    }
}

impl TextEncrypt for Chacha20Poly1305 {
    fn encrypt(&self, mut reader: impl Read) -> anyhow::Result<Vec<Vec<u8>>> {
        let mut input_buf = Vec::new();
        reader.read_to_end(&mut input_buf)?;

        let key = GenericArray::clone_from_slice(&self.key);
        let nonce = chacha20poly1305::ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let cipher = chacha20poly1305::ChaCha20Poly1305::new(&key);
        let ciphertext = cipher.encrypt(&nonce, input_buf.as_ref());
        let ciphertext = match ciphertext {
            Ok(ciphertext) => ciphertext,
            Err(e) => {
                return Err(anyhow::anyhow!("encrypt failed: {}", e.to_string()));
            }
        };
        Ok(vec![ciphertext, nonce.to_vec()])
    }
}

impl TextDecrypt for Chacha20Poly1305 {
    fn decrypt(&self, mut reader: impl Read) -> anyhow::Result<Vec<u8>> {
        let mut input_buf = String::new();
        reader.read_to_string(&mut input_buf)?;
        let input_buf = input_buf.trim().to_string();

        let ciphertext_info: Vec<&str> = input_buf.split(':').collect();
        if ciphertext_info.len() != 2 {
            return Err(anyhow::anyhow!("invalid ciphertext"));
        }
        let ciphertext = BASE64_URL_SAFE_NO_PAD.decode(ciphertext_info[0])?;
        let nonce = BASE64_URL_SAFE_NO_PAD.decode(ciphertext_info[1])?;

        let nonce = Nonce::from_slice(&nonce);
        let key = GenericArray::clone_from_slice(&self.key);
        let cipher = chacha20poly1305::ChaCha20Poly1305::new(&key);
        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref());
        let plaintext = match plaintext {
            Ok(plaintext) => plaintext,
            Err(e) => {
                return Err(anyhow::anyhow!("decrypt failed: {}", e.to_string()));
            }
        };
        Ok(plaintext)
    }
}

impl Blake3 {
    fn new(key: [u8; 32]) -> Self {
        Self { key }
    }
    fn try_new(key: &[u8]) -> anyhow::Result<Self> {
        let key = &key[..32];
        let key = key.try_into()?;
        let signer = Self::new(key);
        Ok(signer)
    }
}

impl Ed25519Signer {
    fn new(key: SigningKey) -> Self {
        Self { key }
    }
    fn try_new(key: &[u8]) -> anyhow::Result<Self> {
        let key = SigningKey::from_bytes(key.try_into()?);
        let signer = Self::new(key);
        Ok(signer)
    }
}

impl Ed25519Verifier {
    fn new(key: VerifyingKey) -> Self {
        Self { key }
    }
    fn try_new(key: &[u8]) -> anyhow::Result<Self> {
        let key = VerifyingKey::from_bytes(key.try_into()?)?;
        let signer = Self::new(key);
        Ok(signer)
    }
}

impl Chacha20Poly1305 {
    fn new(key: [u8; 32]) -> Self {
        Self { key }
    }
    fn try_new(key: &[u8]) -> anyhow::Result<Self> {
        let key = &key[..32];
        let key = key.try_into()?;
        let encryptor = Self::new(key);
        Ok(encryptor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_blake3_sign_verify() -> anyhow::Result<()> {
        let blake3 = Blake3::load("./tests/text_test/blake3.txt")?;
        let data = b"hello world";
        let sig = blake3.sign(&mut &data[..])?;
        assert!(blake3.verify(&data[..], &sig)?);
        Ok(())
    }

    #[test]
    fn test_ed25519_sign_verify() -> anyhow::Result<()> {
        let sk = Ed25519Signer::load("./tests/text_test/ed25519.sk")?;
        let pk = Ed25519Verifier::load("./tests/text_test/ed25519.pk")?;
        let data = b"hello world";
        let sig = sk.sign(&mut &data[..])?;
        assert!(pk.verify(&data[..], &sig)?);
        Ok(())
    }

    #[test]
    fn test_chacha20poly1305_encrypt() -> anyhow::Result<()> {
        let plaintext = "./tests/text_test/chacha20poly1305.txt";
        let key = "./tests/text_test/chacha20poly1305.key";
        let mode = TextEncryptFormat::Chacha20Poly1305;
        assert!(process_encrypt(plaintext, key, mode).is_ok());
        Ok(())
    }

    #[test]
    fn test_chacha20poly1305_decrypt() -> anyhow::Result<()> {
        let ciphertext = "./tests/text_test/chacha20poly1305Ciphertext.txt";
        let key = "./tests/text_test/chacha20poly1305.key";
        let plaintext = "./tests/text_test/chacha20poly1305.txt";
        let mode = TextEncryptFormat::Chacha20Poly1305;

        let plain_by_decrypt = process_decrypt(ciphertext, key, mode)?;
        let mut reader = get_reader(plaintext)?;
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let encode = BASE64_URL_SAFE_NO_PAD.encode(buf);

        assert_eq!(plain_by_decrypt, encode);
        Ok(())
    }
}
