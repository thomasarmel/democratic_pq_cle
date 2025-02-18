pub mod binary_matrix_operations;
pub mod certificateless_qc_mdpc;
pub mod math;
pub mod my_bool;
pub use crate::certificateless_qc_mdpc::utils;
pub const N_0: usize = 2; // Encryption code length, multiplied by code dimension. This is the inverse of the code rate
pub const P: usize = 8009; // Encryption code dimension
pub const W: usize = 100; // Parity-check matrix weight
pub const T: usize = 50; // errors count, to be determined
pub const VOTES_THRESHOLD: f32 = 0.66; // Vote threshold for new node acceptance
const SIG_K: usize = 160; // Signature secret generator dimension
const SIG_N: usize = 2000; // Signature public parity-check matrix length
const SIG_N_PRIME: usize = 1000; // Signature secret generator length
const SIG_R: usize = 1100; // Signature public parity-check matrix dimension
const SIGNATURE_WEIGHT_INTERVAL: [usize; 2] = [470, 530]; // Interval for acceptable signature weight. Weight outside this interval will be rejected