use num::Integer;
use num::integer::binomial;
use num_primes::Generator;
use shamir_secret_sharing::num_bigint::BigInt;
use democratic_pq_cle::certificateless_qc_mdpc::{generate_random_weight_vector_to_invertible_matrix, CertificatelessQcMdpc};
use shamir_secret_sharing::ShamirSecretSharing as SSS;
use democratic_pq_cle::math::nth_combination;
use democratic_pq_cle::my_bool::MyBool;

const P: usize = 401;
const W: usize = 100;
const T: usize = 6;
const VOTES_THRESHOLD: f32 = 0.5;

const MESSAGE: &'static str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX";
const NODE_ID: usize = 1;

fn main() {
    let shamir_prime = BigInt::from(Generator::new_prime(P << 2));

    //let si_weight = max((W >> 1).nth_root(3), 10); // ???
    let si_weight = 7;//(W >> 1).nth_root(3); // TODO il faudrait au moins 7 pour securité, 13 pour P = 4000

    let binomial_coef_s_i_generation = binomial(BigInt::from(P), BigInt::from(si_weight));

    let s_i_node_1 = generate_random_weight_vector_to_invertible_matrix(P, si_weight);
    //println!("s_i: {:?}", s_i);
    let node_1 = CertificatelessQcMdpc::init(NODE_ID, P, W, T, &s_i_node_1);
    let (node_1_public_key, node_1_witness_vector) = node_1.public_key_and_witness_vector();
    println!("Node 1: Public key verified: {}", node_1_public_key.check_is_valid(NODE_ID, &s_i_node_1, &node_1_witness_vector, W));
    let node_1_private_key = node_1.private_key();
    //println!("Public key: {:?}", public_key);
    let encrypted = node_1_public_key.encrypt(MESSAGE.as_bytes());
    let encrypted_bis = node_1_public_key.encrypt(MESSAGE.as_bytes()); // as decryption is probabilist, it increases the chance to decrypt the message
    //println!("Encrypted: {}", encrypted);

    let decrypted = node_1_private_key.decrypt(&encrypted).or(node_1_private_key.decrypt(&encrypted_bis)).unwrap();
    //println!("Decrypted: {:?}", decrypted);
    println!("Node 1: Decrypted data: {}", std::str::from_utf8(&decrypted[0..MESSAGE.len()]).unwrap());

    // The signature should be broadcast to all nodes, in order to allow all nodes to verify the new node initialization vector
    let new_node_2_signature = node_1.accept_new_node(2);
    println!("New node 2 signature valid: {}", new_node_2_signature.is_valid(&node_1_witness_vector, 2));

    let sss = SSS {
        threshold: 1,
        share_amount: 1,
        prime: shamir_prime,
    };
    //println!("{}", new_node_2_signature.to_shamir_share(1).1);
    //println!("{}", sss.recover(&[new_node_2_signature.to_shamir_share(1)]));
    let s_node_2_combination_index = sss.recover(&[new_node_2_signature.to_shamir_share(1)]).mod_floor(&binomial_coef_s_i_generation);
    //println!("{}", s_node_2_combination_index);
    let mut s_i_node_2 = vec![MyBool::from(false); P];
    for index_to_flip in nth_combination(P, si_weight, s_node_2_combination_index.to_biguint().unwrap()) {
        s_i_node_2[index_to_flip] = MyBool::from(true);
    }
    //println!("s_i_node_2: {:?}", s_i_node_2);
    let node_1 = CertificatelessQcMdpc::init(2, P, W, T, &s_i_node_2);
    let (node_2_public_key, node_2_witness_vector) = node_1.public_key_and_witness_vector();
    println!("Node 2: Public key verified: {}", node_2_public_key.check_is_valid(2, &s_i_node_2, &node_2_witness_vector, W));

    let node_2_private_key = node_1.private_key();
    //println!("Public key: {:?}", public_key);
    let encrypted = node_2_public_key.encrypt(MESSAGE.as_bytes());
    let encrypted_bis = node_2_public_key.encrypt(MESSAGE.as_bytes()); // as decryption is probabilist, it increases the chance to decrypt the message
    //println!("Encrypted: {}", encrypted);

    let decrypted = node_2_private_key.decrypt(&encrypted).or(node_2_private_key.decrypt(&encrypted_bis)).unwrap();
    //println!("Decrypted: {:?}", decrypted);
    println!("Node 2: Decrypted data: {}", std::str::from_utf8(&decrypted[0..MESSAGE.len()]).unwrap());
}
