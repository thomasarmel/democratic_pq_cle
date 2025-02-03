mod encryption_private_key;
mod encryption_public_key;
mod new_node_acceptance_signature;
pub mod utils;
mod witness_signing_pub_key;

use crate::binary_matrix_operations::{
    concat_horizontally_mat, make_circulant_matrix, make_identity_matrix,
};
use crate::certificateless_qc_mdpc::encryption_private_key::CertificatelessQcMdpcPrivateKey;
use crate::certificateless_qc_mdpc::encryption_public_key::CertificatelessQcMdpcPublicKey;
use crate::certificateless_qc_mdpc::new_node_acceptance_signature::NewNodeAcceptanceSignature;
use crate::certificateless_qc_mdpc::utils::{
    check_vector_leads_to_invertible_circulant_matrix, generate_hash_id_vector_correct_weight,
    generate_random_weight_vector, generate_random_weight_vector_to_invertible_matrix,
};
use crate::certificateless_qc_mdpc::witness_signing_pub_key::NodeWitnessSigPubKey;
use crate::math::{binom, nth_combination};
use crate::my_bool::MyBool;
use crate::{N_0, SIG_K, SIG_N, SIG_N_PRIME, SIG_R};
use nalgebra::DMatrix;
use num::integer::Roots;
use num_bigint::RandBigInt;
use crate::utils::{try_invert_matrix_vector, multiply_2_matrix_first_line_vector};

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
        let h_i_3_weight = w >> 1;
        let h_i_1 = generate_hash_id_vector_correct_weight(id, p, h_i_1_weight);
        assert!(check_vector_leads_to_invertible_circulant_matrix(&h_i_1, p)); // What to do otherwise?

        //println!("h_i_1: {:?}", h_i_1);

        let h_i_2 = generate_random_weight_vector_to_invertible_matrix(p, h_i_2_weight);
        //println!("h_i_2: {:?}", h_i_2);

        //println!("h_i_3: generated");
        let h_i_3 = generate_random_weight_vector(p, h_i_3_weight);
        //println!("h_i_3: {:?}", h_i_3);

        let sig_a = make_circulant_matrix(
            &generate_random_weight_vector_to_invertible_matrix(SIG_K, SIG_K.nth_root(3)),
            SIG_K,
            SIG_K,
            1,
        );
        let mut sig_g = make_identity_matrix(SIG_K);
        let b = generate_random_weight_vector(SIG_N_PRIME - SIG_K, SIG_K);
        let B = make_circulant_matrix(&b, SIG_K, SIG_N_PRIME - SIG_K, 1);
        concat_horizontally_mat(&mut sig_g, &B);

        let sig_sk_generator = sig_a * sig_g;

        let mut rng = rand::thread_rng();
        let j_comb_index =
            rng.gen_biguint_below(&binom(SIG_N, SIG_N_PRIME));
        let j_comb = nth_combination(SIG_N, SIG_N_PRIME, j_comb_index);

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
        let h_i_1_inv = try_invert_matrix_vector(&self.h_i_1).unwrap();
        let h_i_2_inv = try_invert_matrix_vector(&self.h_i_2).unwrap();
        let s_i_inv = try_invert_matrix_vector(&self.secret_vector).unwrap();

        let r_i = multiply_2_matrix_first_line_vector(&h_i_2_inv, &self.h_i_3);
        let R_i = make_circulant_matrix(&r_i, self.p, self.p, 1);
        let right_part_generator = make_circulant_matrix(&multiply_2_matrix_first_line_vector(&multiply_2_matrix_first_line_vector(&multiply_2_matrix_first_line_vector(&s_i_inv, &h_i_1_inv), &h_i_2_inv), &self.h_i_3), self.p, self.p, 1).transpose();

        //let right_part_generator = (S_i_inv * H_i_1_inv * H_i_2_inv * H_i_3).transpose();

        let mut generator = make_identity_matrix(self.p);
        concat_horizontally_mat(&mut generator, &right_part_generator);

        let mut signature_parity_matrix = make_identity_matrix(SIG_R);
        let R_i_truncated: DMatrix<MyBool> = R_i.columns(0, SIG_N - SIG_R).into();
        let R_i_truncated: DMatrix<MyBool> = R_i_truncated.rows(0, SIG_R).into();
        concat_horizontally_mat(&mut signature_parity_matrix, &R_i_truncated);

        let mut signature_parity_matrix_truncated =
            DMatrix::from_element(SIG_R, SIG_N_PRIME, MyBool::from(false));
        for col_num in 0..signature_parity_matrix_truncated.ncols() {
            signature_parity_matrix_truncated.set_column(
                col_num,
                &signature_parity_matrix.column(self.sig_j[col_num]),
            );
        }
        let signature_multiplication_matrix =
            signature_parity_matrix_truncated * self.sig_sk_generator.clone().transpose();

        (
            CertificatelessQcMdpcPublicKey {
                generator_matrix: generator,
                max_message_size_bits: self.p,
                errors_count: self.t,
            },
            NodeWitnessSigPubKey {
                pubkey_witness_vector: r_i,
                signature_parity_matrix: signature_parity_matrix,
                signature_multiplication_matrix,
            },
        )
    }

    #[allow(non_snake_case)]
    pub fn private_key(&self) -> CertificatelessQcMdpcPrivateKey {
        let H_i_3 = make_circulant_matrix(&self.h_i_3, self.p, self.p, 1);

        let mut parity_check_matrix = H_i_3;
        let right_part_parity_check = make_circulant_matrix(&multiply_2_matrix_first_line_vector(&multiply_2_matrix_first_line_vector(&self.h_i_2, &self.h_i_1), &self.secret_vector), self.p, self.p, 1);

        concat_horizontally_mat(&mut parity_check_matrix, &right_part_parity_check);

        CertificatelessQcMdpcPrivateKey {
            parity_check_matrix,
            expected_encoded_vector_size: self.n,
        }
    }

    #[allow(non_snake_case)]
    pub fn accept_new_node(&self, new_node_id: usize) -> NewNodeAcceptanceSignature {
        // Returns Shamir's share
        let mut generator_star: DMatrix<MyBool> =
            DMatrix::from_element(SIG_K, SIG_N, MyBool::from(false));
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
