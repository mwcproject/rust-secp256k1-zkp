#![no_main]
use libfuzzer_sys::fuzz_target;

extern crate secp256k1zkp;

use secp256k1zkp::{
    AggSigPartialSignature,
    ContextFlag,
    Message,
    Secp256k1,
    PublicKey,
    SecretKey
};

use secp256k1zkp::aggsig::AggSigContext;
use secp256k1zkp::rand::TryRng;
use secp256k1zkp::rand::rngs::SysRng;

fuzz_target!(|data: &[u8]| {
    let numkeys = 3;
    if data.len() < (numkeys + 1) * 32 {
        return ();
    }

    let mut rng = &mut SysRng;
    let secp = Secp256k1::with_caps(ContextFlag::Full).unwrap();
    let mut pks: Vec<PublicKey> = Vec::with_capacity(numkeys);
    let mut keypairs: Vec<(SecretKey, PublicKey)> = Vec::with_capacity(numkeys);

    for i in 0..numkeys {
        if let Ok(sk) = SecretKey::from_slice(&secp, &data[i*32..(i+1)*32]) {
            let pk = PublicKey::from_secret_key(&secp, &sk).unwrap();
            pks.push(pk.clone());
            keypairs.push((sk, pk));
        } else {
            // Invalid data if regenarated intentionally. As a result, tests will not be reproducable, it is accepted.
            // The harness is not input-deterministic - it is expected
            let (sk, pk) = secp.generate_keypair(&mut rng).unwrap();
            pks.push(pk.clone());
            keypairs.push((sk, pk));
        }
    }

    let mut aggsig = AggSigContext::new(&pks).unwrap();

    for i in 0..numkeys {
        if aggsig.generate_nonce(i).unwrap() != true {
            panic!("failed to generate aggsig nonce: {}", i);
        }
    }

    let mut msg_in = [0u8; 32];
    rng.try_fill_bytes(&mut msg_in).unwrap();
    let msg = Message::from_slice(&msg_in).unwrap();
 
    let mut partial_sigs: Vec<AggSigPartialSignature> = vec![];

    for (i, (ss, _)) in keypairs.iter().enumerate() {
        match aggsig.partial_sign(msg.clone(), ss.clone(), i) {
            Ok(res) => partial_sigs.push(res),
            Err(e) => panic!("error creating partial signature: {:?}", e),
        }
    }

    match aggsig.combine_signatures(&partial_sigs) {
        Ok(full_sig) => {
            if !aggsig.verify(full_sig, msg.clone()).unwrap() {
                panic!("aggsig.verify return false")
            }
            ()
        },
        Err(e) => panic!("error combining signatures: {:?}", e),
    }
});
