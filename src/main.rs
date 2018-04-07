extern crate ring;
extern crate untrusted;
// extern crate rand;

use ring::{aead, digest, agreement, rand, error};
// use untrusted;

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

fn ecdh_example() -> Result<(), error::Unspecified> {
    let rng = rand::SystemRandom::new();
    // let rng = rand::thread_rng();

    let my_private_key =
        agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng)?;

    // Make `my_public_key` a byte slice containing my public key. In a real
    // application, this would be sent to the peer in an encoded protocol
    // message.
    let mut my_public_key = [0u8; agreement::PUBLIC_KEY_MAX_LEN];
    let my_public_key =
        &mut my_public_key[..my_private_key.public_key_len()];
    my_private_key.compute_public_key(my_public_key)?;

    // In a real application, the peer public key would be parsed out of a
    // protocol message. Here we just generate one.
    let mut peer_public_key_buf = [0u8; agreement::PUBLIC_KEY_MAX_LEN];
    println!("public key lenth: {:?}", agreement::PUBLIC_KEY_MAX_LEN);
    println!("my public key lenth: {:?}", my_private_key.public_key_len());
    let peer_public_key;
    {
        let peer_private_key =
            agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng)?;
        peer_public_key =
            &mut peer_public_key_buf[..peer_private_key.public_key_len()];
        peer_private_key.compute_public_key(peer_public_key)?;
    }
    let peer_public_key = untrusted::Input::from(peer_public_key);

    // In a real application, the protocol specifies how to determine what
    // algorithm was used to generate the peer's private key. Here, we know it
    // is X25519 since we just generated it.
    let peer_public_key_alg = &agreement::X25519;

    let shared_secret = agreement::agree_ephemeral(my_private_key, peer_public_key_alg,
                                                   peer_public_key, ring::error::Unspecified,
                                                   |_key_material| {
                                                       // Usually, apply actual kdf
                                                       Ok(())
                                                       // error::Unspecified(())
                                                       // error::Err()

                                                   })?;
    println!("shared_secret: {:?}", shared_secret);
    Ok(())
}



fn main() {
    // sha256_example();
    // aead_example();
    println!("{:?}", ecdh_example());

}

