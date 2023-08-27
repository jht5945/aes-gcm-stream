use benchmark_simple::{Bench, Options};

use aes_gcm_stream::{Aes128GcmStreamEncryptor, Aes192GcmStreamEncryptor, Aes256GcmStreamEncryptor};

fn test_aes128_encrypt(m: &mut [u8]) {
    let key = [0u8; 16];
    let nonce = [0u8; 12];
    let mut encryptor = Aes128GcmStreamEncryptor::new(key, &nonce);

    encryptor.update(m);
    encryptor.finalize();
}

fn test_aes192_encrypt(m: &mut [u8]) {
    let key = [0u8; 24];
    let nonce = [0u8; 12];
    let mut encryptor = Aes192GcmStreamEncryptor::new(key, &nonce);

    encryptor.update(m);
    encryptor.finalize();
}

fn test_aes256_encrypt(m: &mut [u8]) {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let mut encryptor = Aes256GcmStreamEncryptor::new(key, &nonce);

    encryptor.update(m);
    encryptor.finalize();
}

fn main() {
    let bench = Bench::new();
    let mut m = vec![0xd0u8; 16384];

    let options = &Options {
        iterations: 1_000,
        warmup_iterations: 1_00,
        min_samples: 5,
        max_samples: 10,
        max_rsd: 1.0,
        ..Default::default()
    };

    let res = bench.run(options, || test_aes128_encrypt(&mut m));
    println!("AES128 encrypt  : {}", res.throughput(m.len() as _));

    let res = bench.run(options, || test_aes192_encrypt(&mut m));
    println!("AES192 encrypt  : {}", res.throughput(m.len() as _));

    let res = bench.run(options, || test_aes256_encrypt(&mut m));
    println!("AES256 encrypt  : {}", res.throughput(m.len() as _));
}