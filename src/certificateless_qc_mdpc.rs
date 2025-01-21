use crate::binary_matrix_operations::{concat_horizontally_mat, make_circulant_matrix, make_identity_matrix, matrix_is_zero, try_inverse_matrix};
use crate::math::nth_combination;
use crate::my_bool::MyBool;
use crate::N_0;
use nalgebra::DMatrix;
use num::integer::{binomial, Roots};
use num::{One, Zero};
use num_bigint::{BigInt, BigUint, RandBigInt};
use rand::Rng;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sha3::{Digest, Sha3_512};
use std::cmp::{max, min};

const SIG_K: usize = 32;
const SIGNATURE_WEIGHT_INTERVAL: [usize; 2] = [90, 110];

#[derive(Debug, Clone)]
pub struct CertificatelessQcMdpc {
    p: usize,
    t: usize,
    n: usize,
    w: usize,
    secret_vector: Vec<MyBool>,
    h_i_1: Vec<MyBool>,
    h_i_2: Vec<MyBool>,
    h_i_3: Vec<MyBool>,
    node_id: usize,
    sig_sk_generator: DMatrix<MyBool>,
    sig_j: Vec<usize>,
}

impl CertificatelessQcMdpc {
    #[allow(non_snake_case)]
    pub fn init(id: usize, p: usize, w: usize, t: usize, si: &[MyBool]) -> Self {
        assert!(check_vector_leads_to_invertible_circulant_matrix(si, p));
        assert_eq!(si.len(), p);

        let h_i_1_weight = (w >> 1).nth_root(3);
        let h_i_2_weight = (w >> 1).nth_root(3);
        let h_i_3_weight = w >> 2;//w >> 1; // TODO still secure ???
        let h_i_1 = generate_hash_id_vector_correct_weight(id, p, h_i_1_weight);
        assert!(check_vector_leads_to_invertible_circulant_matrix(&h_i_1, p)); // What to do otherwise?

        //println!("h_i_1: {:?}", h_i_1);

        let h_i_2 = generate_random_weight_vector_to_invertible_matrix(p, h_i_2_weight);
        //println!("h_i_2: {:?}", h_i_2);

        //println!("h_i_3: generated");
        let h_i_3 = generate_random_weight_vector(p, h_i_3_weight);
        //println!("h_i_3: {:?}", h_i_3);

        let sig_a = make_circulant_matrix(&generate_random_weight_vector(SIG_K, SIG_K >> 1), SIG_K, SIG_K, 1);
        let mut sig_g = make_identity_matrix(SIG_K);
        let n_prime = p >> 1;
        let b = generate_random_weight_vector(n_prime - SIG_K, SIG_K);
        let B = make_circulant_matrix(&b, SIG_K, n_prime - SIG_K, 1);
        concat_horizontally_mat(&mut sig_g, &B);
        let sig_sk_generator = sig_a * sig_g;

        let mut rng = rand::thread_rng();
        let j_comb_index = rng.gen_biguint_below(&binomial(BigUint::from(p), BigUint::from(n_prime)));
        let j_comb = nth_combination(p, n_prime, j_comb_index);

        Self {
            p,
            t,
            n: p * N_0,
            w,
            secret_vector: si.to_vec(),
            h_i_1,
            h_i_2,
            h_i_3,
            node_id: id,
            sig_sk_generator,
            sig_j: j_comb,
        }
    }

    #[allow(non_snake_case)]
    pub fn public_key_and_witness(&self) -> (CertificatelessQcMdpcPublicKey, NodeWitnessSigPubKey) {
        let H_i_1 = make_circulant_matrix(&self.h_i_1, self.p, self.p, 1);
        let H_i_2 = make_circulant_matrix(&self.h_i_2, self.p, self.p, 1);
        let H_i_3 = make_circulant_matrix(&self.h_i_3, self.p, self.p, 1);
        let S_i = make_circulant_matrix(&self.secret_vector, self.p, self.p, 1);
        let S_i_inv = try_inverse_matrix(&S_i).unwrap();
        let H_i_1_inv = try_inverse_matrix(&H_i_1).unwrap();
        let H_i_2_inv = try_inverse_matrix(&H_i_2).unwrap();

        let R_i = H_i_2_inv.clone() * H_i_3.clone();
        let r_i: Vec<MyBool> = R_i.row(0).iter().cloned().collect();
        assert_eq!(make_circulant_matrix(&r_i, self.p, self.p, 1), R_i); // todo not useful

        let right_part_generator = (S_i_inv * H_i_1_inv * H_i_2_inv * H_i_3).transpose();

        let mut generator = make_identity_matrix(self.p);
        concat_horizontally_mat(&mut generator, &right_part_generator);

        let n_prime = self.p >> 1;
        let r = self.p >> 1;
        let mut signature_parity_matrix = make_identity_matrix(r);
        let R_i_truncated: DMatrix<MyBool> = R_i.columns(0, self.p - r).into();
        let R_i_truncated: DMatrix<MyBool> = R_i_truncated.rows(0, r).into();
        concat_horizontally_mat(&mut signature_parity_matrix, &R_i_truncated);

        let mut signature_parity_matrix_truncated = DMatrix::from_element(r, n_prime, MyBool::from(false));
        for col_num in 0..signature_parity_matrix_truncated.ncols() {
            signature_parity_matrix_truncated.set_column(col_num, &signature_parity_matrix.column(self.sig_j[col_num]));
        }
        let signature_multiplication_matrix = signature_parity_matrix_truncated * self.sig_sk_generator.clone().transpose();

        (CertificatelessQcMdpcPublicKey {
            generator_matrix: generator,
            max_message_size_bits: self.p,
            errors_count: self.t,
        },
         NodeWitnessSigPubKey {
             pubkey_witness_vector: r_i,
             signature_parity_matrix: signature_parity_matrix,
             signature_multiplication_matrix,
         })
    }

    #[allow(non_snake_case)]
    pub fn private_key(&self) -> CertificatelessQcMdpcPrivateKey {
        let H_i_1 = make_circulant_matrix(&self.h_i_1, self.p, self.p, 1);
        let H_i_2 = make_circulant_matrix(&self.h_i_2, self.p, self.p, 1);
        let H_i_3 = make_circulant_matrix(&self.h_i_3, self.p, self.p, 1);
        let S_i = make_circulant_matrix(&self.secret_vector, self.p, self.p, 1);

        let mut parity_check_matrix = H_i_3;
        let right_part_parity_check = H_i_2 * H_i_1 * S_i;

        concat_horizontally_mat(&mut parity_check_matrix, &right_part_parity_check);

        CertificatelessQcMdpcPrivateKey {
            parity_check_matrix,
            expected_encoded_vector_size: self.n,
        }
    }

    #[allow(non_snake_case)]
    pub fn accept_new_node(&self, new_node_id: usize) -> NewNodeAcceptanceSignature { // Returns Shamir's share
        let mut generator_star: DMatrix<MyBool> = DMatrix::from_element(SIG_K, self.p, MyBool::from(false));
        for row in 0..generator_star.nrows() {
            for col in 0..generator_star.ncols() {
                let current_col_pos_in_sig_j = self.sig_j.iter().position(|&c| c == col);
                match current_col_pos_in_sig_j {
                    None => {}
                    Some(col_pos) => {
                        generator_star[(row, col)] = self.sig_sk_generator[(row, col_pos)]
                    }
                }
            }
        }
        let h_other_1 = generate_hash_id_vector_correct_weight(new_node_id, SIG_K, SIG_K >> 1);
        let H_other_1: DMatrix<MyBool> = DMatrix::from_column_slice(1, SIG_K, &h_other_1);

        NewNodeAcceptanceSignature {
            signature: H_other_1 * generator_star,
            signing_node_id: self.node_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeWitnessSigPubKey {
    pub pubkey_witness_vector: Vec<MyBool>,
    pub signature_parity_matrix: DMatrix<MyBool>,
    pub signature_multiplication_matrix: DMatrix<MyBool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificatelessQcMdpcPublicKey {
    generator_matrix: DMatrix<MyBool>,
    max_message_size_bits: usize,
    errors_count: usize,
}

impl CertificatelessQcMdpcPublicKey {
    #[allow(non_snake_case)]
    pub fn encrypt(&self, data: &[u8]) -> DMatrix<MyBool> {
        assert!(data.len() << 3 <= self.max_message_size_bits);
        let mut message = DMatrix::from_element(1, self.max_message_size_bits, MyBool::from(false));
        for i in 0..min(self.max_message_size_bits, data.len() << 3) { // wrong check
            message[(0, i)] = MyBool::from(data[i >> 3] & (1 << (i & 7)) != 0);
        }
        let G = self.generator_matrix.clone();
        let e = self.get_error_vector();
        (message * G) + e
    }

    #[allow(non_snake_case)]
    pub fn check_is_valid(&self, node_id: usize, s_i: &[MyBool], witness: &NodeWitnessSigPubKey, weight: usize) -> bool {
        let r_i: &[MyBool] = witness.pubkey_witness_vector.as_ref();
        if self.max_message_size_bits != s_i.len()
        || self.max_message_size_bits != r_i.len() {
            return false;
        }
        let S_i = make_circulant_matrix(&s_i, self.max_message_size_bits, self.max_message_size_bits, 1);
        let S_i_inv = match try_inverse_matrix(&S_i) {
            None => return false,
            Some(inverse_matrix) => inverse_matrix,
        };
        let h_i_1_weight = (weight >> 1).nth_root(3);
        let h_i_1 = generate_hash_id_vector_correct_weight(node_id, self.max_message_size_bits, h_i_1_weight);
        let H_i_1 = make_circulant_matrix(&h_i_1, self.max_message_size_bits, self.max_message_size_bits, 1);
        let H_i_1_inv = match try_inverse_matrix(&H_i_1) {
            None => return false,
            Some(inverse_matrix) => inverse_matrix,
        };

        let R_i = make_circulant_matrix(r_i, self.max_message_size_bits, self.max_message_size_bits, 1);

        let G_i_verif_right_part = (S_i_inv * H_i_1_inv * R_i).transpose();
        let mut G_i_verif = make_identity_matrix(self.max_message_size_bits);
        concat_horizontally_mat(&mut G_i_verif, &G_i_verif_right_part);
        G_i_verif == self.generator_matrix
    }

    fn get_error_vector(&self) -> DMatrix<MyBool> {
        let n = self.max_message_size_bits * N_0;
        let mut rng = ChaCha20Rng::from_entropy();
        let mut error_vector = DMatrix::from_element(1, n, MyBool::from(false));
        let mut weight = 0usize;
        while weight < self.errors_count {
            let idx = rng.gen_range(0..n);
            if !*error_vector[(0, idx)] {
                error_vector[(0, idx)] = MyBool::from(true);
                weight += 1;
            }
        }
        error_vector
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificatelessQcMdpcPrivateKey {
    parity_check_matrix: DMatrix<MyBool>,
    expected_encoded_vector_size: usize,
}

impl CertificatelessQcMdpcPrivateKey {
    pub fn decrypt(&self, data: &DMatrix<MyBool>) -> Result<Vec<u8>, &'static str> {
        if data.ncols() != self.expected_encoded_vector_size {
            return Err("Invalid data size");
        }

        let mut encoded_data = data.clone();
        //let H = self.parity_check_matrix.clone();
        let mut syn = self.parity_check_matrix.clone() * encoded_data.transpose();
        //println!("{} {} {} {}", data.nrows(), data.ncols(), syn.nrows(), syn.ncols());
        let limit = 10usize;
        let delta = 5usize;
        for _i in 0..limit {
            let mut unsatisfied = vec![0usize; encoded_data.ncols()];
            for j in 0..encoded_data.ncols() {
                for k in 0..self.parity_check_matrix.nrows() {
                    if **self.parity_check_matrix.get((k, j)).unwrap() && **syn.get((k, 0)).unwrap() {
                        unsatisfied[j] += 1;
                    }
                }
            }
            let b = max((*unsatisfied.iter().max().unwrap() as i32) - delta as i32, 0) as usize;
            for j in 0..encoded_data.ncols() {
                if unsatisfied[j] > b {
                    **(encoded_data.get_mut((0, j)).unwrap()) ^= true;
                    syn += self.parity_check_matrix.view_range(0..self.parity_check_matrix.nrows(), j..j + 1);
                }
            }

            //println!("Round {}: {} unsatisfied, sum of syn = {} (is zero = {})", _i, *unsatisfied.iter().max().unwrap() as i32, matrix_elements_sum(&syn), matrix_is_zero(&syn));

            if matrix_is_zero(&syn) {
                let mut result = vec![0u8; encoded_data.ncols() << 3];
                for col in 0..encoded_data.ncols() {
                    result[col >> 3] |= (**encoded_data.get((0, col)).unwrap() as u8) << (col & 7);
                }
                return Ok(result);
            }
        }
        Err("Decoding failed")
    }

    pub fn decrypt_syndrome(&self, syndrome: &DMatrix<MyBool>) -> Result<Vec<bool>, &'static str> {
        let ncols = syndrome.nrows() << 1;
        if ncols != self.expected_encoded_vector_size {
            return Err("Invalid data size");
        }

        let mut error = vec![false; ncols];
        let mut syn = syndrome.clone();
        let limit = 10usize;
        let delta = 5usize;
        for _i in 0..limit {
            let mut unsatisfied = vec![0usize; ncols];
            for j in 0..ncols {
                for k in 0..self.parity_check_matrix.nrows() {
                    if **self.parity_check_matrix.get((k, j)).unwrap() && **syn.get((k, 0)).unwrap() {
                        unsatisfied[j] += 1;
                    }
                }
            }
            let b = (*unsatisfied.iter().max().unwrap()).abs_diff(delta);//max((*unsatisfied.iter().max().unwrap() as i32) - delta as i32, 0) as usize;
            for j in 0..ncols {
                if unsatisfied[j] > b {
                    error[j] ^= true;
                    syn += self.parity_check_matrix.view_range(0..self.parity_check_matrix.nrows(), j..j + 1);
                }
            }

            //println!("Round {}: {} unsatisfied, sum of syn = {} (is zero = {})", _i, *unsatisfied.iter().max().unwrap() as i32, matrix_elements_sum(&syn), matrix_is_zero(&syn));

            if matrix_is_zero(&syn) {
                return Ok(error);
            }
        }
        Err("Decoding failed")
    }

    pub fn weight(&self) -> usize {
        self.parity_check_matrix.row(0).iter().filter(|b| ***b).count()
    }

    pub fn first_line(&self) -> Vec<MyBool> {
        self.parity_check_matrix.row(0).iter().cloned().collect()
    }
}

impl ToString for CertificatelessQcMdpcPrivateKey {
    fn to_string(&self) -> String {
        let mut s = String::new();
        for i in 0..self.parity_check_matrix.nrows() {
            for j in 0..self.parity_check_matrix.ncols() {
                s.push(if **self.parity_check_matrix.get((i, j)).unwrap() { '1' } else { '0' });
            }
            s.push('\n');
        }
        s
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewNodeAcceptanceSignature {
    signing_node_id: usize,
    signature: DMatrix<MyBool>
}

impl NewNodeAcceptanceSignature {
    #[allow(non_snake_case)]
    pub fn is_valid(&self, signer_node_witness: &NodeWitnessSigPubKey, new_node_id: usize) -> bool {
        let h_other_1 = generate_hash_id_vector_correct_weight(new_node_id, SIG_K, SIG_K >> 1);
        let H_other_1: DMatrix<MyBool> = DMatrix::from_column_slice(1, SIG_K, &h_other_1);

        let signature_weight = self.signature.row(0).iter().filter(|x| ***x).count();

        if signature_weight < SIGNATURE_WEIGHT_INTERVAL[0] || signature_weight > SIGNATURE_WEIGHT_INTERVAL[1] {
            println!("Wrong signature weight: {}", signature_weight);
            return false;
        }

        signer_node_witness.signature_multiplication_matrix.clone() * H_other_1.transpose() == signer_node_witness.signature_parity_matrix.clone() * self.signature.transpose()
    }

    pub fn to_shamir_share(&self) -> (usize, BigInt) {
        let mut share_eval = BigInt::zero();
        let mut pos_counter = 0usize;
        for row in 0..self.signature.nrows() {
            for col in 0..self.signature.ncols() {
                if **self.signature.get((row, col)).unwrap() {
                    share_eval += BigInt::one() << pos_counter;
                }
                pos_counter += 1;
            }
        }
        (self.signing_node_id, share_eval)
    }
}

fn generate_random_weight_vector(size: usize, weight: usize) -> Vec<MyBool> {
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

fn check_vector_leads_to_invertible_circulant_matrix(vector: &[MyBool], p: usize) -> bool {
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

fn generate_hash_id_vector_correct_weight(id: usize, k: usize, weight: usize) -> Vec<MyBool> {
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