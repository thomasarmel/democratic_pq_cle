pub mod binary_matrix_operations;
pub mod certificateless_qc_mdpc;
pub mod math;
pub mod my_bool;
pub use crate::certificateless_qc_mdpc::utils;
pub const N_0: usize = 2;

const SIG_K: usize = 160; // must be changed when changing P
const SIGNATURE_WEIGHT_INTERVAL: [usize; 2] = [900, 1100];
pub const P: usize = 4001;
pub const W: usize = 127;
pub const T: usize = 50; // errors count, to be determined
pub const VOTES_THRESHOLD: f32 = 0.66;