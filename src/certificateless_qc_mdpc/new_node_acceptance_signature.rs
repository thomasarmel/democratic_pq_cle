use nalgebra::DMatrix;
use num::{One, Zero};
use num_bigint::BigInt;
use crate::certificateless_qc_mdpc::{generate_hash_id_vector_correct_weight, NodeWitnessSigPubKey, SIGNATURE_WEIGHT_INTERVAL, SIG_K};
use crate::my_bool::MyBool;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewNodeAcceptanceSignature {
    pub(super) signing_node_id: usize,
    pub(super) signature: DMatrix<MyBool>
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