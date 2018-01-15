extern crate ring;

use ring::{aead, digest};

fn aead_example() {
    // Pick our algorithm and message to send
    let aead_alg = &aead::AES_128_GCM;
    let message = vec![1, 2, 7, 8, 9, 10, 11, 12];

    // Set key, nonce, ad (extra authenticated data). Here, ad is empty
    let key_bytes = vec![0u8; aead_alg.key_len()];
    let nonce = vec![0u8; aead_alg.nonce_len()];
    let ad = vec![0u8; 0];  // additional authenticated data.

    // Make a buffer, in_out, that holds the message and extra
    // bytes for the MAC tag. seal_in_place will put the entire
    // ciphertext in this buffer
    let mut in_out = message.clone();
    in_out.extend(vec![0u8; aead_alg.tag_len()]);

    // Make the sealing key, the key encrypt/signing
    let sealing_key = aead::SealingKey::new(aead_alg, &key_bytes).unwrap();

    // Encrypt and sign in_out. Result is saved to in_out
    let ct_len = aead::seal_in_place(&sealing_key, &nonce, &ad,
                                     &mut in_out, aead_alg.tag_len()).unwrap();
    assert_eq!(ct_len, in_out.len());
    let ct = in_out.clone();

    // TODO: read this closer: https://briansmith.org/rustdoc/ring/aead/fn.open_in_place.html

    // Make the opening key for authenticating and decrypting
    let opening_key = aead::OpeningKey::new(aead_alg, &key_bytes).unwrap();

    // Decrypt ("open") and authenticate in_out. Result is saved to in_out
    let in_prefix_len = 0;  // Not used in this example. See docs for more info.
    let open_pt = aead::open_in_place(&opening_key, &nonce, &ad,
                                      in_prefix_len, &mut in_out).unwrap();

    assert_eq!(message, open_pt);
    println!("message: {:?}", message);
    println!("ct: {:?}", ct);
    println!("opened pt: {:?}", open_pt);
}

fn sha256_example() {
    let digest_alg = &digest::SHA256;
    let mut ctx = digest::Context::new(digest_alg);
    let hello_world_bytes = vec![104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100];
    ctx.update(&hello_world_bytes);
    let digest = ctx.finish();
    println!("Digest: {:?}", digest);
}

fn main() {
    sha256_example();
    aead_example();
}

