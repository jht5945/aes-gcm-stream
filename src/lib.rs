use aes::Aes128;
use aes::cipher::{Block, BlockEncrypt, KeyInit};
use aes::cipher::generic_array::GenericArray;

pub struct Aes128GcmStreamEncryptor {
    crypto: Aes128,
    message_buffer: Vec<u8>,
    integrality_buffer: Vec<u8>,
    ghash_key: u128,
    ghash_val: u128,
    init_nonce: u128,
    encryption_nonce: u128,
    adata_len: usize,
    message_len: usize,
}

impl Aes128GcmStreamEncryptor {
    pub fn new(key: [u8; 16]) -> Self {
        let key = GenericArray::from(key);
        let aes = Aes128::new(&key);

        Self {
            crypto: aes,
            message_buffer: vec![],
            integrality_buffer: vec![],
            ghash_key: 0,
            ghash_val: 0,
            init_nonce: 0,
            encryption_nonce: 0,
            adata_len: 0,
            message_len: 0,
        }
    }

    pub fn init_nonce(&mut self, nonce: &[u8]) {
        let (ghash_key, normalized_nonce) = self.normalize_nonce(nonce);
        self.ghash_key = ghash_key;
        self.init_nonce = normalized_nonce;
        self.encryption_nonce = normalized_nonce;
    }

    pub fn init_adata(&mut self, adata: &[u8]) {
        self.integrality_buffer.extend_from_slice(adata);
        self.adata_len += adata.len();

        let adata_bit_len = self.adata_len * 8;
        let v = 128 * ((adata_bit_len + 128 - 1) / 128) - adata_bit_len;
        self.integrality_buffer.extend_from_slice(&vec![0x00; v / 8]);
    }

    pub fn next(&mut self, bytes: &[u8]) -> Vec<u8> {
        self.message_buffer.extend_from_slice(bytes);
        let message_buffer_slice = self.message_buffer.as_slice();
        let message_buffer_len = message_buffer_slice.len();
        if message_buffer_len < 16 {
            return vec![];
        }
        let blocks_count = message_buffer_len / 16;
        let mut encrypted_message = vec![];
        for i in 0..blocks_count {
            self.encryption_nonce = inc_32(self.encryption_nonce);
            let mut ctr = self.encryption_nonce.to_be_bytes();
            let block = Block::<Aes128>::from_mut_slice(&mut ctr);
            self.crypto.encrypt_block(block);
            let chunk = &message_buffer_slice[i * 16..(i + 1) * 16];
            let y = u8to128(chunk) ^ u8to128(&block.as_slice());
            encrypted_message.extend_from_slice(&y.to_be_bytes());
        }
        self.message_buffer = message_buffer_slice[blocks_count * 16..].to_vec();
        self.integrality_buffer.extend_from_slice(&encrypted_message);
        self.message_len += encrypted_message.len();

        self.update_integrality_buffer();

        encrypted_message
    }

    pub fn finalize(&mut self) -> (Vec<u8>, Vec<u8>) {
        let mut encrypted_message = vec![];
        if !self.message_buffer.is_empty() {
            // last block and this block len is less than 128 bits
            self.encryption_nonce = inc_32(self.encryption_nonce);
            let mut ctr = self.encryption_nonce.to_be_bytes();
            let block = Block::<Aes128>::from_mut_slice(&mut ctr);
            self.crypto.encrypt_block(block);

            let chunk = self.message_buffer.as_slice();
            let msb = msb_s(chunk.len() * 8, block.as_slice());
            let y = u8to128(chunk) ^ u8to128(&msb);
            encrypted_message.extend_from_slice(&y.to_be_bytes()[16 - chunk.len()..16]);
            self.integrality_buffer.extend_from_slice(&encrypted_message);
            self.message_len += encrypted_message.len();
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

        (encrypted_message, tag)
    }

    fn calculate_tag(&mut self) -> Vec<u8> {
        let mut bs = self.init_nonce.to_be_bytes().clone();
        let block = Block::<Aes128>::from_mut_slice(&mut bs);
        self.crypto.encrypt_block(block);
        let tag_trunk = self.ghash_val.to_be_bytes();
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
                self.ghash_val = gmul_128(self.ghash_val ^ u8to128(buf), self.ghash_key)
            }
            self.integrality_buffer = integrality_buffer_slice[blocks_count * 16..].to_vec();
        }
    }

    fn ghash_key(&mut self) -> u128 {
        let mut block = [0u8; 16];
        let block = Block::<Aes128>::from_mut_slice(&mut block);
        self.crypto.encrypt_block(block);
        u8to128(&block.as_slice())
    }

    fn normalize_nonce(&mut self, nonce_bytes: &[u8]) -> (u128, u128) {
        let ghash_key = self.ghash_key();
        normalize_nonce(ghash_key, nonce_bytes)
    }
}

fn normalize_nonce(ghash_key: u128, nonce_bytes: &[u8]) -> (u128, u128) {
    let nonce = u8to128(nonce_bytes);
    let normalized_nonce = match nonce_bytes.len() == 12 {
        true => {
            nonce << 32 | 0x00000001
        }
        false => {
            let mut iv_padding = vec![];
            // s = 128[len(iv) / 128] - len(iv)
            let s = 128 * (((nonce_bytes.len() * 8) + 128 - 1) / 128) - (nonce_bytes.len() * 8);
            iv_padding.push(nonce << s);
            iv_padding.push((nonce_bytes.len() * 8) as u128);
            ghash(ghash_key, &iv_padding)
        }
    };
    (ghash_key, normalized_nonce)
}

// R = 11100001 || 0(120)
const R: u128 = 0b11100001 << 120;

fn gmul_128(x: u128, y: u128) -> u128 {
    let mut z = 0u128;
    let mut v = y;
    for i in (0..128).rev() {
        let xi = (x >> i) & 1;
        if xi != 0 {
            z ^= v;
        }
        v = match v & 1 == 0 {
            true => { v >> 1 }
            false => { (v >> 1) ^ R }
        };
    }
    z
}

fn ghash(key: u128, messages: &[u128]) -> u128 {
    let mut y = 0u128;
    for i in 0..messages.len() {
        let yi = gmul_128(y ^ messages[i], key);
        y = yi;
    }
    y
}

fn u8to128(bytes: &[u8]) -> u128 {
    bytes.iter().rev().enumerate().fold(0, |acc, (i, &byte)| {
        acc | (byte as u128) << (i * 8)
    })
}

fn msb_s(s: usize, bytes: &[u8]) -> Vec<u8> {
    let mut result = vec![];
    let n = s / 8;
    let remain = s % 8;
    for i in 0..n {
        result.push(bytes[i]);
    }
    if remain > 0 {
        result.push(bytes[n] >> (8 - remain));
    }
    result
}

// incs(X)=MSBlen(X)-s(X) || [int(LSBs(X))+1 mod 2^s]s
fn inc_32(bits: u128) -> u128 {
    let msb = bits >> 32;
    let mut lsb = (bits & 0xffffffff) as u32;
    lsb = lsb.wrapping_add(1);
    msb << 32 | lsb as u128
}