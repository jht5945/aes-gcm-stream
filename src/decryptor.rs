use aes::{Aes128, Aes192, Aes256};
use aes::cipher::{Block, BlockEncrypt, KeyInit};
use aes::cipher::generic_array::GenericArray;
use zeroize::ZeroizeOnDrop;

use crate::util::{gmul_128, inc_32, msb_s, normalize_nonce, u8to128};

macro_rules! define_aes_gcm_stream_decryptor_impl {
    (
        $module:tt,
        $aesn:tt,
        $key_size:tt
    ) => {

#[derive(ZeroizeOnDrop)]
pub struct $module {
    crypto: $aesn,
    message_buffer: Vec<u8>,
    integrality_buffer: Vec<u8>,
    ghash_key: u128,
    ghash_val: u128,
    init_nonce: u128,
    encryption_nonce: u128,
    adata_len: usize,
    message_len: usize,
}

impl $module {
    pub fn new(key: [u8; $key_size], nonce: &[u8]) -> Self {
        let key = GenericArray::from(key);
        let aes = $aesn::new(&key);

        let mut s = Self {
            crypto: aes,
            message_buffer: vec![],
            integrality_buffer: vec![],
            ghash_key: 0,
            ghash_val: 0,
            init_nonce: 0,
            encryption_nonce: 0,
            adata_len: 0,
            message_len: 0,
        };
        let (ghash_key, normalized_nonce) = s.normalize_nonce(nonce);
        println!("<<< KEY: {}", hex::encode(ghash_key.to_be_bytes()));
        s.ghash_key = ghash_key;
        s.init_nonce = normalized_nonce;
        s.encryption_nonce = normalized_nonce;
        s
    }

    pub fn init_adata(&mut self, adata: &[u8]) {
        self.integrality_buffer.extend_from_slice(adata);
        self.adata_len += adata.len();

        let adata_bit_len = self.adata_len * 8;
        let v = 128 * ((adata_bit_len + 128 - 1) / 128) - adata_bit_len;
        self.integrality_buffer.extend_from_slice(&vec![0x00; v / 8]);
    }

    pub fn update(&mut self, bytes: &[u8]) -> Vec<u8> {
        self.message_buffer.extend_from_slice(bytes);
        let message_buffer_slice = self.message_buffer.as_slice();
        let message_buffer_len = message_buffer_slice.len();
        if message_buffer_len < 32 {
            return Vec::with_capacity(0);
        }
        let blocks_count = (message_buffer_len / 16) - 1;
        let mut plaintext_message = Vec::with_capacity(blocks_count * 16);
        for i in 0..blocks_count {
            self.encryption_nonce = inc_32(self.encryption_nonce);
            let mut ctr = self.encryption_nonce.to_be_bytes();
            let block = Block::<$aesn>::from_mut_slice(&mut ctr);
            self.crypto.encrypt_block(block);
            let chunk = &message_buffer_slice[i * 16..(i + 1) * 16];
            let y = u8to128(chunk) ^ u8to128(&block.as_slice());
            plaintext_message.extend_from_slice(&y.to_be_bytes());
        }
        self.integrality_buffer.extend_from_slice(&message_buffer_slice[0..blocks_count * 16]);
        self.message_buffer = message_buffer_slice[blocks_count * 16..].to_vec();
        self.message_len += plaintext_message.len();

        self.update_integrality_buffer();

        plaintext_message
    }

    pub fn finalize(&mut self) -> Result<Vec<u8>, String> {
        let mut plaintext_message = Vec::with_capacity(16);
        let message_buffer_len = self.message_buffer.len();
        if message_buffer_len > 16 {
            // last block and this block len is less than 128 bits
            self.encryption_nonce = inc_32(self.encryption_nonce);
            let mut ctr = self.encryption_nonce.to_be_bytes();
            let block = Block::<$aesn>::from_mut_slice(&mut ctr);
            self.crypto.encrypt_block(block);

            let chunk = &self.message_buffer[0..message_buffer_len - 16];
            let msb = msb_s(chunk.len() * 8, block.as_slice());
            let y = u8to128(chunk) ^ u8to128(&msb);
            plaintext_message.extend_from_slice(&y.to_be_bytes()[16 - chunk.len()..16]);
            self.integrality_buffer.extend_from_slice(&self.message_buffer[0..message_buffer_len - 16]);
            self.message_len += plaintext_message.len();
        }
        let adata_bit_len = self.adata_len * 8;
        let message_bit_len = self.message_len * 8;
        let u = 128 * ((message_bit_len + 128 - 1) / 128) - message_bit_len;
        self.integrality_buffer.extend_from_slice(&vec![0x00; u / 8]);
        self.integrality_buffer.extend_from_slice(&(adata_bit_len as u64).to_be_bytes());
        self.integrality_buffer.extend_from_slice(&(message_bit_len as u64).to_be_bytes());

        self.update_integrality_buffer();
        assert!(self.integrality_buffer.is_empty());

        let tag = self.calculate_tag();
        let message_tag = &self.message_buffer[message_buffer_len - 16..];

        if message_tag != tag.as_slice() {
            Err(format!("Tag mismatch, expected: {:2x}, actual: {:2x}",
                        u8to128(&tag), u8to128(message_tag)))
        } else {
            Ok(plaintext_message)
        }
    }

    fn calculate_tag(&mut self) -> Vec<u8> {
        let mut bs = self.init_nonce.to_be_bytes().clone();
        let block = Block::<$aesn>::from_mut_slice(&mut bs);
        self.crypto.encrypt_block(block);
        println!("<<< final enc block: {}", hex::encode(&block.as_slice()));
        let tag_trunk = self.ghash_val.to_be_bytes();
        println!("<<< final block: {}", hex::encode(&tag_trunk));
        let y = u8to128(&tag_trunk) ^ u8to128(&block.as_slice());
        y.to_be_bytes().to_vec()
    }

    fn update_integrality_buffer(&mut self) {
        let integrality_buffer_slice = self.integrality_buffer.as_slice();
        let integrality_buffer_slice_len = integrality_buffer_slice.len();
        if integrality_buffer_slice_len >= 16 {
            let blocks_count = integrality_buffer_slice_len / 16;
            for i in 0..blocks_count {
                let buf = &integrality_buffer_slice[i * 16..(i + 1) * 16];
                println!("<<< block: {}", hex::encode(buf));
                self.ghash_val = gmul_128(self.ghash_val ^ u8to128(buf), self.ghash_key)
            }
            self.integrality_buffer = integrality_buffer_slice[blocks_count * 16..].to_vec();
        }
    }

    fn ghash_key(&mut self) -> u128 {
        let mut block = [0u8; 16];
        let block = Block::<$aesn>::from_mut_slice(&mut block);
        self.crypto.encrypt_block(block);
        u8to128(&block.as_slice())
    }

    fn normalize_nonce(&mut self, nonce_bytes: &[u8]) -> (u128, u128) {
        let ghash_key = self.ghash_key();
        normalize_nonce(ghash_key, nonce_bytes)
    }
}
    }
}

define_aes_gcm_stream_decryptor_impl!(Aes128GcmStreamDecryptor, Aes128, 16);
define_aes_gcm_stream_decryptor_impl!(Aes192GcmStreamDecryptor, Aes192, 24);
define_aes_gcm_stream_decryptor_impl!(Aes256GcmStreamDecryptor, Aes256, 32);
