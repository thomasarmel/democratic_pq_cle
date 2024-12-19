use num::Integer;
use num::integer::{binomial, Roots};
use num_primes::Generator;
use shamir_secret_sharing::num_bigint::BigInt;
use democratic_pq_cle::certificateless_qc_mdpc::{generate_random_weight_vector_to_invertible_matrix, CertificatelessQcMdpc};
use shamir_secret_sharing::ShamirSecretSharing as SSS;
use democratic_pq_cle::math::nth_combination;
use democratic_pq_cle::my_bool::MyBool;

const P: usize = 401;
const W: usize = 100;
const T: usize = 5; // errors count, to be determined
const VOTES_THRESHOLD: f32 = 0.66;

const MESSAGE: &'static str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX";

fn main() {
    /*let A = make_circulant_matrix(&generate_random_weight_vector(500, 15), 100, 100, 1);
    let B = make_circulant_matrix(&generate_random_weight_vector(500, 15), 100, 100, 1);
    let C = A * B;
    let c: Vec<MyBool> = C.row(0).iter().cloned().collect();
    println!("c: {:?}", c.iter().filter(|b| ***b).count());

    return;*/
    let shamir_prime = BigInt::from(Generator::new_prime(P << 2));

    //let si_weight = max((W >> 1).nth_root(3), 10); // ???
    let si_weight = (W >> 1).nth_root(2);//7;//(W >> 1).nth_root(3); // TODO il faudrait au moins 7 pour securité, 13 pour P = 4000

    let binomial_coef_s_i_generation = binomial(BigInt::from(P), BigInt::from(si_weight));

    let mut nodes_currently_in_system_count = 0;

    // Init node 1, using a random s_i vector

    let s_i_node_1 = generate_random_weight_vector_to_invertible_matrix(P, si_weight);
    //println!("s_i: {:?}", s_i);
    let node_1 = CertificatelessQcMdpc::init(1, P, W, T, &s_i_node_1);
    nodes_currently_in_system_count += 1;
    let (node_1_public_key, node_1_witness) = node_1.public_key_and_witness();
    println!("Node 1: Public key verified: {}", node_1_public_key.check_is_valid(1, &s_i_node_1, &node_1_witness, W));
    let node_1_private_key = node_1.private_key();
    //println!("Public key: {:?}", public_key);
    let encrypted = node_1_public_key.encrypt(MESSAGE.as_bytes());
    let encrypted_bis = node_1_public_key.encrypt(MESSAGE.as_bytes()); // as decryption is probabilist, it increases the chance to decrypt the message
    //println!("Encrypted: {}", encrypted);

    let decrypted = node_1_private_key.decrypt(&encrypted).or(node_1_private_key.decrypt(&encrypted_bis)).unwrap();
    //println!("Decrypted: {:?}", decrypted);
    println!("Node 1: Decrypted data: {}", std::str::from_utf8(&decrypted[0..MESSAGE.len()]).unwrap());

    // Node 1 accepts the new node 2

    // The signature should be broadcast to all nodes, in order to allow all nodes to verify the new node initialization vector
    let new_node_2_signature_from_node_1 = node_1.accept_new_node(2);
    println!("New node 2 signature valid from node 1: {}", new_node_2_signature_from_node_1.is_valid(&node_1_witness, 2));

    let shamir_voting_threshold = ((nodes_currently_in_system_count as f32) * VOTES_THRESHOLD).ceil() as usize;
    println!("Accepting a new node... Voting threshold = {}", shamir_voting_threshold);
    let sss = SSS {
        threshold: shamir_voting_threshold,
        share_amount: 1,
        prime: shamir_prime.clone(),
    };
    //println!("{}", new_node_2_signature.to_shamir_share(1).1);
    //println!("{}", sss.recover(&[new_node_2_signature.to_shamir_share(1)]));
    let s_node_2_combination_index = sss.recover(&[new_node_2_signature_from_node_1.to_shamir_share()]).mod_floor(&binomial_coef_s_i_generation);
    //println!("{}", s_node_2_combination_index);
    let mut s_i_node_2 = vec![MyBool::from(false); P];
    for index_to_flip in nth_combination(P, si_weight, s_node_2_combination_index.to_biguint().unwrap()) {
        s_i_node_2[index_to_flip] = MyBool::from(true);
    }
    //println!("s_i_node_2: {:?}", s_i_node_2);
    let node_2 = CertificatelessQcMdpc::init(2, P, W, T, &s_i_node_2);
    nodes_currently_in_system_count += 1;
    let (node_2_public_key, node_2_witness) = node_2.public_key_and_witness();
    println!("Node 2: Public key verified: {}", node_2_public_key.check_is_valid(2, &s_i_node_2, &node_2_witness, W));

    let node_2_private_key = node_2.private_key();
    //println!("Public key: {:?}", public_key);
    let encrypted = node_2_public_key.encrypt(MESSAGE.as_bytes());
    let encrypted_bis = node_2_public_key.encrypt(MESSAGE.as_bytes()); // as decryption is probabilist, it increases the chance to decrypt the message
    //println!("Encrypted: {}", encrypted);

    let decrypted = node_2_private_key.decrypt(&encrypted).or(node_2_private_key.decrypt(&encrypted_bis)).unwrap();
    //println!("Decrypted: {:?}", decrypted);
    println!("Node 2: Decrypted data: {}", std::str::from_utf8(&decrypted[0..MESSAGE.len()]).unwrap());

    // Node 1 and 2 accepts the new node 3
    let new_node_3_signature_from_node_1 = node_1.accept_new_node(3);
    let new_node_3_signature_from_node_2 = node_2.accept_new_node(3);
    println!("New node 3 signature valid from node 1: {}", new_node_3_signature_from_node_1.is_valid(&node_1_witness, 3));
    println!("New node 3 signature valid from node 2: {}", new_node_3_signature_from_node_2.is_valid(&node_2_witness, 3));

    let shamir_voting_threshold = ((nodes_currently_in_system_count as f32) * VOTES_THRESHOLD).ceil() as usize;
    println!("Accepting a new node... Voting threshold = {}", shamir_voting_threshold);
    let sss = SSS {
        threshold: shamir_voting_threshold,
        share_amount: 1,
        prime: shamir_prime.clone(),
    };
    let s_node_3_combination_index = sss.recover(&[
        new_node_3_signature_from_node_1.to_shamir_share(),
        new_node_3_signature_from_node_2.to_shamir_share(),
    ]).mod_floor(&binomial_coef_s_i_generation);
    let mut s_i_node_3 = vec![MyBool::from(false); P];
    for index_to_flip in nth_combination(P, si_weight, s_node_3_combination_index.to_biguint().unwrap()) {
        s_i_node_3[index_to_flip] = MyBool::from(true);
    }
    let node_3 = CertificatelessQcMdpc::init(3, P, W, T, &s_i_node_3);
    nodes_currently_in_system_count += 1;
    let (node_3_public_key, node_3_witness) = node_3.public_key_and_witness();
    println!("Node 3: Public key verified: {}", node_3_public_key.check_is_valid(3, &s_i_node_3, &node_3_witness, W));
    let node_3_private_key = node_3.private_key();
    let encrypted = node_3_public_key.encrypt(MESSAGE.as_bytes());
    let encrypted_bis = node_3_public_key.encrypt(MESSAGE.as_bytes()); // as decryption is probabilist, it increases the chance to decrypt the message
    let decrypted = node_3_private_key.decrypt(&encrypted).or(node_3_private_key.decrypt(&encrypted_bis)).unwrap();
    //println!("Decrypted: {:?}", decrypted);
    println!("Node 3: Decrypted data: {}", std::str::from_utf8(&decrypted[0..MESSAGE.len()]).unwrap());

    println!("Nodes currently in system: {}", nodes_currently_in_system_count);
}
