use num::integer::Roots;
use democratic_pq_cle::certificateless_qc_mdpc::{generate_random_weight_vector_to_invertible_matrix, CertificatelessQcMdpc};

const P: usize = 401;
const W: usize = 60;
const T: usize = 6;

const MESSAGE: &'static str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX";

fn main() {
    //let si_weight = max((W >> 1).nth_root(3), 10); // ???
    let si_weight = (W >> 1).nth_root(3);
    let s_i = generate_random_weight_vector_to_invertible_matrix(P, si_weight);
    //println!("s_i: {:?}", s_i);
    let code = CertificatelessQcMdpc::init(1, P, W, T, &s_i);
    let (public_key, witness_vector) = code.public_key_and_witness_vector();
    println!("Public key verified: {}", public_key.check_is_valid(1, &s_i, &witness_vector, W));
    let private_key = code.private_key();
    //println!("Public key: {:?}", public_key);
    let encrypted = public_key.encrypt(MESSAGE.as_bytes());
    //println!("Encrypted: {}", encrypted);

    let decrypted = private_key.decrypt(&encrypted).unwrap();
    //println!("Decrypted: {:?}", decrypted);
    println!("Decrypted data: {}", std::str::from_utf8(&decrypted[0..MESSAGE.len()]).unwrap());
}
