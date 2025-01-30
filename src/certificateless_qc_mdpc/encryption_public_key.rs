use crate::binary_matrix_operations::{
    concat_horizontally_mat, make_circulant_matrix, make_identity_matrix,
};
use crate::certificateless_qc_mdpc::{
    generate_hash_id_vector_correct_weight, NodeWitnessSigPubKey,
};
use crate::my_bool::MyBool;
use crate::N_0;
use nalgebra::DMatrix;
use num::integer::Roots;
use rand::Rng;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use std::cmp::min;
use crate::utils::{multiply_2_matrix_first_line_vector, try_invert_matrix_vector};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificatelessQcMdpcPublicKey {
    pub(super) generator_matrix: DMatrix<MyBool>,
    pub(super) max_message_size_bits: usize,
    pub(super) errors_count: usize,
}

impl CertificatelessQcMdpcPublicKey {
    #[allow(non_snake_case)]
    pub fn encrypt(&self, data: &[u8]) -> DMatrix<MyBool> { // TODO: until decryption works
        assert!(data.len() << 3 <= self.max_message_size_bits);
        let mut message = DMatrix::from_element(1, self.max_message_size_bits, MyBool::from(false));
        for i in 0..min(self.max_message_size_bits, data.len() << 3) {
            // wrong check
            message[(0, i)] = MyBool::from(data[i >> 3] & (1 << (i & 7)) != 0);
        }
        let G = self.generator_matrix.clone();
        let e = self.get_error_vector();
        (message * G) + e
    }

    #[allow(non_snake_case)]
    pub fn check_is_valid(
        &self,
        node_id: usize,
        s_i: &[MyBool],
        witness: &NodeWitnessSigPubKey,
        weight: usize,
    ) -> bool {
        let r_i: &[MyBool] = witness.pubkey_witness_vector.as_ref();
        if self.max_message_size_bits != s_i.len() || self.max_message_size_bits != r_i.len() {
            return false;
        }
        let s_i_inv = match try_invert_matrix_vector(s_i) {
            None => return false,
            Some(inverse_matrix) => inverse_matrix,
        };
        let h_i_1_weight = (weight >> 1).nth_root(3);
        let h_i_1 = generate_hash_id_vector_correct_weight(
            node_id,
            self.max_message_size_bits,
            h_i_1_weight,
        );
        let h_i_1_inv = match try_invert_matrix_vector(&h_i_1) {
            None => return false,
            Some(inverse_matrix) => inverse_matrix,
        };

        let G_i_verif_right_part = make_circulant_matrix(
            &multiply_2_matrix_first_line_vector(&multiply_2_matrix_first_line_vector(&s_i_inv, &h_i_1_inv), r_i),
            self.max_message_size_bits,
            self.max_message_size_bits,
            1,
        ).transpose();
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
