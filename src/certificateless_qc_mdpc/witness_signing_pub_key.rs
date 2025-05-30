use crate::my_bool::MyBool;
use nalgebra::DMatrix;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeWitnessSigPubKey {
    pub pubkey_witness_vector: Vec<MyBool>,
    pub signature_parity_matrix: DMatrix<MyBool>,
    pub signature_multiplication_matrix: DMatrix<MyBool>,
}
