use aes::cipher::KeyInit;
use aes_gcm::{AeadInPlace, Aes128Gcm, Key};
use aes_gcm::aead::{Aead, Nonce};

use aes_gcm_stream::{Aes128GcmStreamDecryptor, Aes128GcmStreamEncryptor};

fn main() {
    let plaintext = [0u8; 69];

    // ---------------------------------------------------------------------------------------

    let key: &[u8; 16] = &[0; 16];
    let key: &Key<Aes128Gcm> = key.into();
    let cipher = Aes128Gcm::new(&key);

    let mut nonce = Nonce::<Aes128Gcm>::default();
    let m: &mut [u8] = nonce.as_mut();
    for i in 0..m.len() {
        m[i] = 0;
    }
    // println!("nonce\t:{}", hex::encode(nonce.as_slice()));

    let ciphertext = cipher.encrypt(&nonce, plaintext.as_slice()).unwrap();
    println!("{}", hex::encode(&ciphertext));
    let mut ciphertext = vec![0u8; plaintext.len()];
    let tag = cipher.encrypt_in_place_detached(&nonce, &[], ciphertext.as_mut_slice()).unwrap();
    println!("{}", hex::encode(&ciphertext));
    println!("{} : TAG", hex::encode(tag.as_slice()));

    let mut ciphertext = plaintext.to_vec();
    cipher.encrypt_in_place(&nonce, &[], &mut ciphertext).unwrap();
    println!("{}", hex::encode(ciphertext.as_slice()));

    let mut aes128_gcm_stream_encryptor = Aes128GcmStreamEncryptor::new([0; 16], &[0u8; 12]);
    aes128_gcm_stream_encryptor.init_adata(&[]);
    let o1 = aes128_gcm_stream_encryptor.next(&plaintext[0..21]);
    let o2 = aes128_gcm_stream_encryptor.next(&plaintext[21..64]);
    let o3 = aes128_gcm_stream_encryptor.next(&[0; 5]);
    let (o4, tag) = aes128_gcm_stream_encryptor.finalize();
    println!("{}: E1", hex::encode(&o1));
    println!("{}: E2", hex::encode(&o2));
    println!("{}: E3", hex::encode(&o3));
    println!("{}: E4", hex::encode(&o4));
    println!("{} : TAG", hex::encode(&tag));

    let mut aes128_gcm_stream_decryptor = Aes128GcmStreamDecryptor::new([0; 16], &[0u8; 12]);
    let o1 = aes128_gcm_stream_decryptor.next(&hex::decode("0388dace60b6a392f328c2b971b2fe78f795aaab494b5923f7fd89ff948bc1e0200211214e7394da2089b6acd093abe0c94da219118e297d7b7ebcbcc9c388f28ade7d85a8c992f32a52151e1c2adceb7c6138e042").unwrap());
    let o2_result = aes128_gcm_stream_decryptor.finalize();
    println!("{}", hex::encode(&o1));
    println!("{:?}", o2_result);
}