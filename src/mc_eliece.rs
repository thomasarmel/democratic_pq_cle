use nalgebra::DMatrix;
use rand::Rng;
use crate::my_bool::MyBool;
use crate::qc_mdpc::{QcMdpc, QcMdpcPrivateKey, QcMdpcPublicKey};

fn get_error_vector(n: usize, error_count: usize) -> DMatrix<MyBool> {
    let mut rng = rand::thread_rng();
    let mut error_vector = DMatrix::from_element(1, n, MyBool::from(false));
    let mut weight = 0usize;
    while weight < error_count {
        let idx = rng.gen_range(0..n);
        if !*error_vector[(0, idx)] {
            error_vector[(0, idx)] = MyBool::from(true);
            weight += 1;
        }
    }

    error_vector
}

pub fn encrypt(public_key: &QcMdpcPublicKey, data: &[u8]) -> Result<DMatrix<MyBool>, &'static str> {
    if data.len() << 3 > public_key.max_message_length() {
        return Err("Data is too long");
    }
    let encoded_data = QcMdpc::encode_data(public_key, data);
    let error_vector = get_error_vector(public_key.encoded_vector_size(), public_key.max_error_weight());
    Ok(
        encoded_data + error_vector
    )
}

pub fn decrypt(private_key: &QcMdpcPrivateKey, data: &DMatrix<MyBool>) -> Result<Vec<u8>, &'static str> {
    if data.ncols() != private_key.expected_encoded_vector_size() {
        return Err("Invalid data size");
    }
    let message = QcMdpc::decode_data(private_key, data)[..private_key.max_message_length()].to_vec();
    Ok(message)
}