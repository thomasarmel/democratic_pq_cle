use num_primes::Generator;
use shamir_secret_sharing::num_bigint::BigInt;
use democratic_pq_cle::certificateless_qc_mdpc::{generate_random_weight_vector_to_invertible_matrix, CertificatelessQcMdpc};
use shamir_secret_sharing::ShamirSecretSharing as SSS;

const P: usize = 401;
const W: usize = 100;
const T: usize = 6;
const VOTES_THRESHOLD: f32 = 0.5;

const MESSAGE: &'static str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX";
const NODE_ID: usize = 1;

fn main() {
    let shamir_prime = BigInt::from(Generator::new_prime(P << 2));

    //let si_weight = max((W >> 1).nth_root(3), 10); // ???
    let si_weight = 7;//(W >> 1).nth_root(3); // TODO il faudrait au moins 7, 13 pour P = 4000
    let s_i = generate_random_weight_vector_to_invertible_matrix(P, si_weight);
    //println!("s_i: {:?}", s_i);
    let code = CertificatelessQcMdpc::init(NODE_ID, P, W, T, &s_i);
    let (public_key, witness_vector) = code.public_key_and_witness_vector();
    println!("Public key verified: {}", public_key.check_is_valid(NODE_ID, &s_i, &witness_vector, W));
    let private_key = code.private_key();
    //println!("Public key: {:?}", public_key);
    let encrypted = public_key.encrypt(MESSAGE.as_bytes());
    let encrypted_bis = public_key.encrypt(MESSAGE.as_bytes()); // as decryption is probabilist, it increases the chance to decrypt the message
    //println!("Encrypted: {}", encrypted);

    let decrypted = private_key.decrypt(&encrypted).or(private_key.decrypt(&encrypted_bis)).unwrap();
    //println!("Decrypted: {:?}", decrypted);
    println!("Decrypted data: {}", std::str::from_utf8(&decrypted[0..MESSAGE.len()]).unwrap());

    let new_node_2_signature = code.accept_new_node(2);
    println!("New node 2 signature valid: {}", new_node_2_signature.is_valid(&witness_vector, 2));

    let sss = SSS {
        threshold: 1,
        share_amount: 1,
        prime: shamir_prime,
    };
    println!("{}", new_node_2_signature.to_shamir_share(1).1);
    println!("{}", sss.recover(&[new_node_2_signature.to_shamir_share(1)]));
}
