use anyhow::Result;
use scrypt::scrypt;
use scrypt::Params;
use sp_core::crypto::SecretStringError;
use sp_core::sr25519;
use sp_core::Pair;
use std::convert::TryInto;
use thiserror::Error;
use xsalsa20poly1305::aead::generic_array::{typenum, GenericArray};
use xsalsa20poly1305::NONCE_SIZE;
use xsalsa20poly1305::{
    aead::{Aead, KeyInit},
    XSalsa20Poly1305,
};

use crate::PAIR_DIV;
use crate::PAIR_HDR;

#[derive(Error, Debug)]
pub enum KeyError {
    #[error("Unsupported ciphertext format")]
    UnsupportedCiphertext,

    #[error("Header error: Invalid or missing header in the data")]
    HeaderError,

    #[error(
        "Decryption initialization vector (DIV) error: Invalid or missing initialization vector"
    )]
    DIVError,

    #[error("Secret string processing error: {0}")]
    SecretStringError(#[from] SecretStringError),

    #[error("Other error: {0}")]
    Other(String),
}

impl From<String> for KeyError {
    fn from(value: String) -> Self {
        Self::Other(value)
    }
}

impl From<&str> for KeyError {
    fn from(value: &str) -> Self {
        Self::Other(value.to_owned())
    }
}

pub fn decode_key<T: AsRef<str>>(password: T, ciphertext: &[u8]) -> Result<String, KeyError> {
    if ciphertext.len() != 201 {
        return Err(KeyError::UnsupportedCiphertext);
    }

    let salt = &ciphertext[0..32];
    let n = u32::from_le_bytes(ciphertext[32..36].try_into().unwrap());
    let p = u32::from_le_bytes(ciphertext[36..40].try_into().unwrap());
    let r = u32::from_le_bytes(ciphertext[40..44].try_into().unwrap());
    let log_n = (n as f32).log2() as u8;

    let params = Params::new(log_n, r, p, 64).map_err(|e| format!("Invalid params, error: {e}"))?;

    let mut derived_key = [0u8; 32];
    scrypt(
        password.as_ref().as_bytes(),
        &salt,
        &params,
        &mut derived_key,
    )
    .map_err(|e| format!("Scrypt failed: {:?}", e))?;

    let nonce: [u8; NONCE_SIZE] = ciphertext[44..68]
        .try_into()
        .map_err(|e| format!("Failed to convert bytes slice to array, error: {e}"))?;
    let plaintext = xsalsa20_poly1305_decrypt(&derived_key, &nonce, &ciphertext[68..]).unwrap();

    if plaintext[0..16] != PAIR_HDR {
        return Err(KeyError::HeaderError);
    }

    let secret_key_bytes = &plaintext[16..80];
    let pair = sr25519::Pair::from_seed_slice(secret_key_bytes)?;

    if plaintext[80..85] != PAIR_DIV {
        return Err(KeyError::DIVError);
    }

    if pair.public().0 != plaintext[85..117] {
        return Err("private key in mismatch with public key".into());
    }

    Ok(hex::encode(secret_key_bytes))
}

fn xsalsa20_poly1305_decrypt(
    key: &[u8],
    nonce: &[u8; NONCE_SIZE],
    ciphertext: &[u8],
) -> Result<Vec<u8>, KeyError> {
    // Create a GenericArray from a fixed-size slice
    let key: GenericArray<u8, typenum::U32> = GenericArray::clone_from_slice(key);

    let cipher = XSalsa20Poly1305::new(&key);

    let plaintext = cipher
        .decrypt(nonce.into(), ciphertext.as_ref())
        .map_err(|e| format!("Failed to decrypt, {e}"))?;
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose, Engine as _};

    #[test]
    fn test_decode() {
        let encoded = "WwDIgSwEa9faPCN3EU2Z0D4tU8o57sQjHeOXtVWUHmkAgAAAAQAAAAgAAABapAN4aXwMevBj9l3fLKIyfOEgtbDlSGUmSrlBboQuGaI12+vWFWFcanolcpkzOCE2xZTgovbnpf+TvhcibOPN0ajQtq6AttW0/W37/7cuMhq7uuBA5COGG7khS3ZA0FADqfWRSQpRCdgmtm0QzOBzJGlT9MtM53wK59d1TK3lHevwrfCH3q852oMOUCxTc1m2dTyoUyYfjDmiPJku";
        let encoded_bytes = general_purpose::STANDARD.decode(encoded).unwrap();
        let private_key_str = decode_key("password", &encoded_bytes).unwrap();
        assert_eq!("3965b5ef16e4811718dc315a02c426b35223ff367bb297b59a15ab8cb4c1a60975a90ca39f373f006dbc23b9504436893dbc1d776297b6b9748ff543730dd006",private_key_str)
    }
}
