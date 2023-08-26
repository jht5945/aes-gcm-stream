use aes::cipher::KeyInit;
use aes_gcm::{AeadInPlace, Aes128Gcm, Key};
use aes_gcm::aead::{Aead, Nonce};

use aes_gcm_stream::Aes128GcmStream;

use crate::copied::GCM;

mod copied;

fn main() {
    let key = [0u8; 16];
    let nonce = [0u8; 12];
    let plaintext = [0u8; 69];
    let mut gcm = GCM::new(key);
    let (tag, enc) = gcm.ae(&nonce, &[], &plaintext);

    println!("{}", hex::encode(&enc));
    println!("{} : TAG", hex::encode(&tag));

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

    let mut aes128_gcm_stream = Aes128GcmStream::new([0; 16]);
    aes128_gcm_stream.init_nonce(&[0u8; 12]);
    aes128_gcm_stream.init_adata(&[]);
    let o1 = aes128_gcm_stream.next(&plaintext[0..21]);
    let o2 = aes128_gcm_stream.next(&plaintext[21..64]);
    let o3 = aes128_gcm_stream.next(&[0; 5]);
    let (o4, t) = aes128_gcm_stream.finalize();
    println!("{}: E1", hex::encode(&o1));
    println!("{}: E2", hex::encode(&o2));
    println!("{}: E3", hex::encode(&o3));
    println!("{}: E4", hex::encode(&o4));
    println!("{} : TAG", hex::encode(&t));
}