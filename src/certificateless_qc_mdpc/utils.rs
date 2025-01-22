use rand::Rng;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sha3::{Digest, Sha3_512};
use crate::binary_matrix_operations::{make_circulant_matrix, try_inverse_matrix};
use crate::my_bool::MyBool;

pub(super) fn generate_random_weight_vector(size: usize, weight: usize) -> Vec<MyBool> {
    let mut rng = ChaCha20Rng::from_entropy();
    let mut secret_vector = vec![MyBool::from(false); size];
    let mut current_weight = 0usize;
    while current_weight < weight {
        let idx = rng.gen_range(0..size);
        if !*secret_vector[idx] {
            secret_vector[idx] = MyBool::from(true);
            current_weight += 1;
        }
    }
    secret_vector
}

pub(super) fn check_vector_leads_to_invertible_circulant_matrix(vector: &[MyBool], p: usize) -> bool {
    let circ = make_circulant_matrix(vector, p, p, 1);
    try_inverse_matrix(&circ).is_some()
}

pub fn generate_random_weight_vector_to_invertible_matrix(size: usize, weight: usize) -> Vec<MyBool> {
    let mut vector = generate_random_weight_vector(size, weight);
    //vector.iter().for_each(|x| print!("{} ", x));
    //println!("");
    //println!("{:?}", vector);
    while !check_vector_leads_to_invertible_circulant_matrix(&vector, size) {
        println!("Regenerating vector");
        vector = generate_random_weight_vector(size, weight);
        while vector[(size >> 1)..size].iter().filter(|b| ***b).count() % 2 == 0 {
            //println!("Regenerating vector bis");
            vector = generate_random_weight_vector(size, weight);
        }
    }
    vector
}

pub(super) fn generate_hash_id_vector_correct_weight(id: usize, k: usize, weight: usize) -> Vec<MyBool> {
    let mut hasher = Sha3_512::new();
    hasher.update(id.to_string());
    let h_id = hasher.finalize().as_slice().to_vec();
    assert!(h_id.iter().map(|x| x.count_ones()).sum::<u32>() >= weight as u32);
    let mut h_i_1 = vec![MyBool::from(false); k];
    let mut current_weight = 0;
    for i in 0..k {
        if h_id[i >> 3] & (1 << (i & 7)) != 0 {
            h_i_1[i] = MyBool::from(true);
            current_weight += 1;
        }
        if current_weight == weight {
            break;
        }
    }
    h_i_1
}