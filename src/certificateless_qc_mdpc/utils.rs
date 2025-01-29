use crate::my_bool::MyBool;
use binary_polynomial_mod_algebra::{BinaryPolynomial, NonZeroBinaryPolynomial};
use num::One;
use num_bigint::BigUint;
use rand::Rng;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sha3::{Digest, Sha3_512};

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

pub(super) fn check_vector_leads_to_invertible_circulant_matrix(
    vector: &[MyBool],
    p: usize,
) -> bool {
    let poly_vec = NonZeroBinaryPolynomial::new(BinaryPolynomial::from(
        vector.iter().map(|x| **x).rev().collect::<Vec<bool>>(),
    ))
    .unwrap();
    let modulus = compute_polynomial_modulus(p);
    poly_vec.inv_mod(&modulus).is_some()
}

pub fn generate_random_weight_vector_to_invertible_matrix(
    size: usize,
    weight: usize,
) -> Vec<MyBool> {
    let mut vector = generate_random_weight_vector(size, weight);
    //vector.iter().for_each(|x| print!("{} ", x));
    //println!("");
    //println!("{:?}", vector);
    while !check_vector_leads_to_invertible_circulant_matrix(&vector, size) {
        println!("Regenerating vector");
        vector = generate_random_weight_vector(size, weight);
        while vector[(size >> 1)..size].iter().filter(|b| ***b).count() % 2 == 0 {
            println!("Regenerating vector bis");
            vector = generate_random_weight_vector(size, weight);
        }
    }
    vector
}

pub(super) fn generate_hash_id_vector_correct_weight(
    id: usize,
    k: usize,
    weight: usize,
) -> Vec<MyBool> {
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

pub(super) fn try_invert_matrix_vector(matrix_first_line: &[MyBool]) -> Option<Vec<MyBool>> {
    let matrix_size = matrix_first_line.len();
    let modulus = compute_polynomial_modulus(matrix_size);
    let polynomial = NonZeroBinaryPolynomial::new(BinaryPolynomial::from(
        matrix_first_line.iter().map(|x| **x).rev().collect::<Vec<bool>>(),
    ));
    let inverse = polynomial.unwrap().inv_mod(&modulus)?;
    let inverse_vector: Vec<bool> = inverse.into();
    let result: Vec<MyBool> = inverse_vector.iter().map(|x| MyBool::from(*x)).rev().collect();
    let result_len = result.len();
    let result = [result, vec![MyBool::from(false); matrix_size - result_len]].concat();
    Some(result)
}

pub(super) fn multiply_2_matrix_first_line_vector(first_line_matrix1: &[MyBool], first_line_matrix2: &[MyBool]) -> Vec<MyBool> {
    assert_eq!(first_line_matrix1.len(), first_line_matrix2.len());
    let matrix_size = first_line_matrix1.len();
    let modulus = compute_polynomial_modulus(matrix_size);
    let polynomial1 = BinaryPolynomial::from(first_line_matrix1.iter().map(|x| **x).rev().collect::<Vec<bool>>());
    let polynomial2 = BinaryPolynomial::from(first_line_matrix2.iter().map(|x| **x).rev().collect::<Vec<bool>>());
    let multiply_vec: Vec<bool> = polynomial1.mul_mod(&polynomial2, &modulus).unwrap().into();
    let result: Vec<MyBool> = multiply_vec.iter().map(|x| MyBool::from(*x)).rev().collect();
    let result_len = result.len();
    [result, vec![MyBool::from(false); matrix_size - result_len]].concat()
}

fn compute_polynomial_modulus(matrix_size: usize) -> NonZeroBinaryPolynomial {
    let mut modulus_biguint = BigUint::one();
    modulus_biguint.set_bit(matrix_size as u64, true);
    NonZeroBinaryPolynomial::new(BinaryPolynomial::from(modulus_biguint)).unwrap()
}