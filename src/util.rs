// R = 11100001 || 0(120)
const R: u128 = 0b11100001 << 120;

pub(crate) fn gmul_128(x: u128, y: u128) -> u128 {
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

pub(crate) fn ghash(key: u128, messages: &[u128]) -> u128 {
    let mut y = 0u128;
    for i in 0..messages.len() {
        let yi = gmul_128(y ^ messages[i], key);
        y = yi;
    }
    y
}

pub(crate) fn normalize_nonce(ghash_key: u128, nonce_bytes: &[u8]) -> (u128, u128) {
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

pub(crate) fn u8to128(bytes: &[u8]) -> u128 {
    bytes.iter().rev().enumerate().fold(0, |acc, (i, &byte)| {
        acc | (byte as u128) << (i * 8)
    })
}

pub(crate) fn msb_s(s: usize, bytes: &[u8]) -> Vec<u8> {
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
pub(crate) fn inc_32(bits: u128) -> u128 {
    let msb = bits >> 32;
    let mut lsb = (bits & 0xffffffff) as u32;
    lsb = lsb.wrapping_add(1);
    msb << 32 | lsb as u128
}