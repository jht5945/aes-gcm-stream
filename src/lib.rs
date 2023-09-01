/// This library is created for AES/GCM stream encrypt or decrypt
///
/// Structs for encryption:
/// * Aes128GcmStreamEncryptor
/// * Aes192GcmStreamEncryptor
/// * Aes256GcmStreamEncryptor
///
/// Structs for decryption:
/// * Aes128GcmStreamDecryptor
/// * Aes192GcmStreamDecryptor
/// * Aes256GcmStreamDecryptor

pub use decryptor::Aes128GcmStreamDecryptor;
pub use decryptor::Aes192GcmStreamDecryptor;
pub use decryptor::Aes256GcmStreamDecryptor;
// ----------------------------------------
pub use encryptor::Aes128GcmStreamEncryptor;
pub use encryptor::Aes192GcmStreamEncryptor;
pub use encryptor::Aes256GcmStreamEncryptor;

mod util;
mod encryptor;
mod decryptor;

mod encryptor2;

#[test]
fn test128() {
    use aes_gcm::{aead::{Aead, Nonce, Payload}, Aes128Gcm, KeyInit};
    let knp = vec![
        ([0; 16], [0; 12], &[] as &[u8], b"Hello World!" as &[u8]),
        ([0; 16], [0; 12], &[1; 16], b"Hello World!" as &[u8]),
        ([0; 16], [0; 12], &[1; 17], b"Hello World!" as &[u8]),
        ([0; 16], [0; 12], &[1; 32], b"Hello World!" as &[u8]),
        ([0; 16], [0; 12], &[1; 64], b"Hello World!" as &[u8]),
        ([0; 16], [0; 12], &[1, 2, 3], b"Hello World!" as &[u8]),
        ([1; 16], [0; 12], &[], b"Hello World!"),
        ([0; 16], [1; 12], &[], b"Hello World!"),
        ([1; 16], [1; 12], &[], b"Hello World ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~!"),
        ([1; 16], [1; 12], &[0; 129], b"Hello World ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~!"),
        ([0xff; 16], [0; 12], &[], b"Hello World!"),
        ([0; 16], [0xff; 12], &[], b"Hello World!"),
        ([0xff; 16], [0xff; 12], &[], b"Hello World ~~~~~~~~~~~~~~~~~\
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\
        ~~~~~~~~~!"),
        ([0xff; 16], [0xff; 12], &[11, 22, 33], b"Hello World ~~~~~~~~~~~~~~~~~\
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\
        ~~~~~~~~~!"),
    ];

    for (key, nonce, aad, plaintext) in knp {
        // encrypt
        let mut ciphertext = vec![];
        let mut encryptor = Aes128GcmStreamEncryptor::new(key.clone(), &nonce);
        if !aad.is_empty() {
            encryptor.init_adata(aad);
        }
        ciphertext.extend_from_slice(&encryptor.update(plaintext));
        let (last_block, tag) = encryptor.finalize();
        ciphertext.extend_from_slice(&last_block);
        ciphertext.extend_from_slice(&tag);

        // decrypt 1
        let mut decryptor = Aes128GcmStreamDecryptor::new(key.clone(), &nonce);
        if !aad.is_empty() {
            decryptor.init_adata(aad);
        }
        let mut plaintext1 = decryptor.update(ciphertext.as_slice());
        let plaintext2 = decryptor.finalize().expect("decryptor decrypt");
        plaintext1.extend_from_slice(&plaintext2);
        assert_eq!(plaintext, plaintext1.as_slice());

        // decrypt 2
        let cipher = Aes128Gcm::new_from_slice(&key).expect("new from key slice");
        let mut decrypt_nonce = Nonce::<Aes128Gcm>::default();
        let m: &mut [u8] = decrypt_nonce.as_mut();
        for i in 0..m.len() {
            m[i] = nonce[i];
        }
        let decrypted_plaintext = if aad.is_empty() {
            cipher.decrypt(&decrypt_nonce, ciphertext.as_slice()).expect("decrypt1")
        } else {
            cipher.decrypt(&decrypt_nonce, Payload {
                msg: ciphertext.as_slice(),
                aad,
            }).expect("decrypt2")
        };
        assert_eq!(plaintext, decrypted_plaintext.as_slice());
    }
}

#[test]
fn test192() {
    let knp = vec![
        ([0; 24], [0; 12], &[] as &[u8], b"Hello World!" as &[u8]),
        ([0; 24], [0; 12], &[1; 16], b"Hello World!" as &[u8]),
        ([0; 24], [0; 12], &[1; 17], b"Hello World!" as &[u8]),
        ([0; 24], [0; 12], &[1; 32], b"Hello World!" as &[u8]),
        ([0; 24], [0; 12], &[1; 64], b"Hello World!" as &[u8]),
        ([0; 24], [0; 12], &[1, 2, 3], b"Hello World!" as &[u8]),
        ([1; 24], [0; 12], &[], b"Hello World!"),
        ([0; 24], [1; 12], &[], b"Hello World!"),
        ([1; 24], [1; 12], &[], b"Hello World ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~!"),
        ([1; 24], [1; 12], &[0; 129], b"Hello World ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~!"),
        ([0xff; 24], [0; 12], &[], b"Hello World!"),
        ([0; 24], [0xff; 12], &[], b"Hello World!"),
        ([0xff; 24], [0xff; 12], &[], b"Hello World ~~~~~~~~~~~~~~~~~\
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\
        ~~~~~~~~~!"),
        ([0xff; 24], [0xff; 12], &[11, 22, 33], b"Hello World ~~~~~~~~~~~~~~~~~\
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\
        ~~~~~~~~~!"),
    ];

    for (key, nonce, aad, plaintext) in knp {
        // encrypt
        let mut ciphertext = vec![];
        let mut encryptor = Aes192GcmStreamEncryptor::new(key.clone(), &nonce);
        if !aad.is_empty() {
            encryptor.init_adata(aad);
        }
        ciphertext.extend_from_slice(&encryptor.update(plaintext));
        let (last_block, tag) = encryptor.finalize();
        ciphertext.extend_from_slice(&last_block);
        ciphertext.extend_from_slice(&tag);

        // decrypt 1
        let mut decryptor = Aes192GcmStreamDecryptor::new(key.clone(), &nonce);
        if !aad.is_empty() {
            decryptor.init_adata(aad);
        }
        let mut plaintext1 = decryptor.update(ciphertext.as_slice());
        let plaintext2 = decryptor.finalize().expect("decryptor decrypt");
        plaintext1.extend_from_slice(&plaintext2);
        assert_eq!(plaintext, plaintext1.as_slice());

        // ops, aes_gcm not supports AES192 bit keys
    }
}

#[test]
fn test256() {
    use aes_gcm::{aead::{Aead, Nonce, Payload}, Aes256Gcm, KeyInit};
    let knp = vec![
        ([0; 32], [0; 12], &[] as &[u8], b"Hello World!" as &[u8]),
        ([0; 32], [0; 12], &[1; 16], b"Hello World!" as &[u8]),
        ([0; 32], [0; 12], &[1; 17], b"Hello World!" as &[u8]),
        ([0; 32], [0; 12], &[1; 32], b"Hello World!" as &[u8]),
        ([0; 32], [0; 12], &[1; 64], b"Hello World!" as &[u8]),
        ([0; 32], [0; 12], &[1, 2, 3], b"Hello World!" as &[u8]),
        ([1; 32], [0; 12], &[], b"Hello World!"),
        ([0; 32], [1; 12], &[], b"Hello World!"),
        ([1; 32], [1; 12], &[], b"Hello World ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~!"),
        ([1; 32], [1; 12], &[0; 129], b"Hello World ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~!"),
        ([0xff; 32], [0; 12], &[], b"Hello World!"),
        ([0; 32], [0xff; 12], &[], b"Hello World!"),
        ([0xff; 32], [0xff; 12], &[], b"Hello World ~~~~~~~~~~~~~~~~~\
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\
        ~~~~~~~~~!"),
        ([0xff; 32], [0xff; 12], &[11, 22, 33], b"Hello World ~~~~~~~~~~~~~~~~~\
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\
        ~~~~~~~~~!"),
    ];

    for (key, nonce, aad, plaintext) in knp {
        println!("======= {} {} {} {}", hex::encode(key), hex::encode(nonce), hex::encode(aad), hex::encode(plaintext));
        // encrypt
        let mut ciphertext = vec![];
        let mut encryptor = Aes256GcmStreamEncryptor::new(key.clone(), &nonce);
        if !aad.is_empty() {
            encryptor.init_adata(aad);
        }
        ciphertext.extend_from_slice(&encryptor.update(plaintext));
        let (last_block, tag) = encryptor.finalize();
        ciphertext.extend_from_slice(&last_block);
        ciphertext.extend_from_slice(&tag);

        // decrypt 1
        let mut decryptor = Aes256GcmStreamDecryptor::new(key.clone(), &nonce);
        if !aad.is_empty() {
            decryptor.init_adata(aad);
        }
        let mut plaintext1 = decryptor.update(ciphertext.as_slice());
        let plaintext2 = decryptor.finalize().expect("decryptor decrypt");
        plaintext1.extend_from_slice(&plaintext2);
        assert_eq!(plaintext, plaintext1.as_slice());

        // decrypt 2
        let cipher = Aes256Gcm::new_from_slice(&key).expect("new from key slice");
        let mut decrypt_nonce = Nonce::<Aes256Gcm>::default();
        let m: &mut [u8] = decrypt_nonce.as_mut();
        for i in 0..m.len() {
            m[i] = nonce[i];
        }
        let decrypted_plaintext = if aad.is_empty() {
            cipher.decrypt(&decrypt_nonce, ciphertext.as_slice()).expect("decrypt1")
        } else {
            cipher.decrypt(&decrypt_nonce, Payload {
                msg: ciphertext.as_slice(),
                aad,
            }).expect("decrypt2")
        };
        assert_eq!(plaintext, decrypted_plaintext.as_slice());
    }
}

#[test]
fn test256_stream() {
    use aes_gcm::{aead::{Aead, Nonce}, Aes256Gcm, KeyInit};
    let key = [0u8; 32];
    let nonce = [0; 12];

    let mut plaintext = vec![];
    // encrypt
    let mut ciphertext = vec![];
    let mut encryptor = Aes256GcmStreamEncryptor::new(key.clone(), &nonce);
    for i in 0..1024 {
        plaintext.extend_from_slice(&[(i % 128) as u8]);
        ciphertext.extend_from_slice(&encryptor.update(&[(i % 128) as u8]));
    }
    let (last_block, tag) = encryptor.finalize();
    ciphertext.extend_from_slice(&last_block);
    ciphertext.extend_from_slice(&tag);


    // decrypt 1
    let mut decryptor = Aes256GcmStreamDecryptor::new(key.clone(), &nonce);
    let mut plaintext1 = vec![];
    for i in 0..ciphertext.len() {
        plaintext1.extend_from_slice(decryptor.update(
            &[ciphertext.as_slice()[i]]).as_slice());
    }
    let plaintext2 = decryptor.finalize().expect("decryptor decrypt");
    plaintext1.extend_from_slice(&plaintext2);
    assert_eq!(plaintext, plaintext1.as_slice());

    // decrypt 2
    let cipher = Aes256Gcm::new_from_slice(&key).expect("new from key slice");
    let mut decrypt_nonce = Nonce::<Aes256Gcm>::default();
    let m: &mut [u8] = decrypt_nonce.as_mut();
    for i in 0..m.len() {
        m[i] = nonce[i];
    }
    let decrypted_plaintext = cipher.decrypt(&decrypt_nonce, ciphertext.as_slice()).expect("decrypt1");
    assert_eq!(plaintext, decrypted_plaintext.as_slice());
}
