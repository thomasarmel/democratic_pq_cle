use std::cmp::{max, min};
use nalgebra::DMatrix;
use rand::Rng;
use crate::binary_matrix_operations::{concat_horizontally_mat, concat_vertically_mat, make_identity_matrix, matrix_is_zero, try_inverse_matrix};
use crate::my_bool::MyBool;

#[derive(Debug, Clone)]
pub struct QcMdpc {
    row: Vec<MyBool>, // 0 or 1
    n0: u32,
    p: u32,
    //w: u32,
    t: u32,
    n: u32,
    k: u32,
    //r: u32,
}

pub struct QcMdpcPublicKey {
    k: u32,
    t: u32,
    n: u32,
    generator_matrix: DMatrix<MyBool>,
}

impl QcMdpcPublicKey {
    pub fn max_message_length(&self) -> usize {
        self.k as usize
    }

    pub(crate) fn max_error_weight(&self) -> usize {
        self.t as usize
    }

    pub(crate) fn encoded_vector_size(&self) -> usize {
        self.n as usize
    }
}

pub struct QcMdpcPrivateKey {
    parity_check_matrix: DMatrix<MyBool>,
    k: u32,
    n: u32,
}

impl QcMdpcPrivateKey {
    pub(crate) fn expected_encoded_vector_size(&self) -> usize {
        self.n as usize
    }

    pub fn max_message_length(&self) -> usize {
        self.k as usize
    }
}

impl QcMdpc {
    pub fn init(n0: u32, p: u32, w: u32, t: u32) -> Self {
        let mut rng = rand::thread_rng();

        let mut code = Self {
            row: vec![MyBool::from(false); (n0 * p) as usize],
            n0,
            p,
            //w,
            t,
            n: n0 * p,
            k: (n0 - 1) * p,
            //r: p,
        };

        let mut parity_check_matrix_invertible = false;

        while !parity_check_matrix_invertible {
            loop {
                let mut flag = 0u32;
                while flag < w {
                    let idx = rng.gen_range(0..=(code.n - 1)) as usize;
                    if !*code.row[idx] {
                        code.row[idx] = MyBool::from(true);
                        flag += 1;
                    }
                }
                if code.get_row_weight(code.k, code.n - 1) % 2 == 1 {
                    break;
                }
                code.row.iter_mut().for_each(|x| *x = MyBool::from(false));
            }
            let p_usize = code.p as usize;
            let circ = make_circulant_matrix(&code.row[((code.n0 as usize - 1) * p_usize)..code.n as usize], p_usize, p_usize, 1);
            if try_inverse_matrix(&circ).is_some() {
                parity_check_matrix_invertible = true;
            } else {
                code.row.iter_mut().for_each(|x| *x = MyBool::from(false));
            }
        }

        code
    }

    pub fn get_public_key(&self) -> QcMdpcPublicKey {
        QcMdpcPublicKey {
            k: self.k,
            t: self.t,
            n: self.n,
            generator_matrix: self.generator_matrix(),
        }
    }

    pub fn get_private_key(&self) -> QcMdpcPrivateKey {
        QcMdpcPrivateKey {
            parity_check_matrix: self.parity_check_matrix(),
            k: self.k,
            n: self.n,
        }
    }

    fn get_row_weight(&self, min_value_included: u32, max_value_included: u32) -> usize {
        self.row[min_value_included as usize..=max_value_included as usize]
            .iter()
            .filter(|&x| **x)
            .count()
    }

    #[allow(non_snake_case)]
    fn parity_check_matrix(&self) -> DMatrix<MyBool> {
        let p_size = self.p as usize;
        let mut H = make_circulant_matrix(&self.row[0..p_size], p_size, p_size, 1);
        for i in 1..self.n0 as usize {
            let M = make_circulant_matrix(&self.row[(i * p_size)..((i+1) * p_size)], p_size, p_size, i);
            concat_horizontally_mat(&mut H, &M);
        }
        H
    }

    #[allow(non_snake_case)]
    fn generator_matrix(&self) -> DMatrix<MyBool> {
        let p_usize = self.p as usize;
        let circ = make_circulant_matrix(&self.row[((self.n0 as usize - 1) * p_usize)..self.n as usize], p_usize, p_usize, 1);
        let H_inv = try_inverse_matrix(&circ).unwrap();
        let H_0 = make_circulant_matrix(&self.row[0..p_usize], p_usize, p_usize, 1);
        let mut Q = (H_inv.clone() * H_0).transpose();
        for i in 1..(self.n0 - 1) as usize {
            let M = make_circulant_matrix(&self.row[(i * p_usize)..((i + 1) * p_usize)], p_usize, p_usize, 1);
            let M = (H_inv.clone() * M).transpose();
            concat_vertically_mat(&mut Q, &M);
        }
        let mut G = make_identity_matrix(self.k as usize);
        concat_horizontally_mat(&mut G, &Q);
        G
    }

    #[allow(non_snake_case)]
    pub(crate) fn encode_data(public_key: &QcMdpcPublicKey, data: &[u8]) -> DMatrix<MyBool> {
        let mut message = DMatrix::from_element(1, public_key.k as usize, MyBool::from(false));
        for i in 0..min(public_key.k as usize, data.len() << 3) { // wrong check
            message[(0, i)] = MyBool::from(data[i >> 3] & (1 << (i & 7)) != 0);
        }
        let G = public_key.generator_matrix.clone();
        message * G
    }

    #[allow(non_snake_case)]
    pub(crate) fn decode_data(private_key: &QcMdpcPrivateKey, encoded_data: &DMatrix<MyBool>) -> Vec<u8> {
        let mut encoded_data = encoded_data.clone();
        let H = private_key.parity_check_matrix.clone();
        let mut syn = H.clone() * encoded_data.transpose();
        let limit = 10usize;
        let delta = 5usize;
        for _i in 0..limit {
            let mut unsatisfied = vec![0usize; encoded_data.ncols()];
            for j in 0..encoded_data.ncols() {
                for k in 0..H.nrows() {
                    if **H.get((k, j)).unwrap() && **syn.get((k, 0)).unwrap() {
                        unsatisfied[j] += 1;
                    }
                }
            }
            let b = max((*unsatisfied.iter().max().unwrap() as i32) - delta as i32, 0) as usize;
            for j in 0..encoded_data.ncols() {
                if unsatisfied[j] > b {
                    **(encoded_data.get_mut((0, j)).unwrap()) ^= true;
                    syn += H.view_range(0..H.nrows(), j..j + 1);
                }
            }

            if matrix_is_zero(&syn) {
                let mut result = vec![0u8; encoded_data.ncols() << 3];
                for col in 0..encoded_data.ncols() {
                    result[col >> 3] |= (**encoded_data.get((0, col)).unwrap() as u8) << (col & 7);
                }
                return result;
            }
        }
        unreachable!("Decoding failed")
    }
}


fn shifted_row(row: &[MyBool], shift: usize) -> Vec<MyBool> {
    let row_len = row.len();
    let mut new_row = vec![MyBool::from(false); row_len];
    for i in 0..row_len {
        new_row[(i + shift) % row_len] = row[i];
    }
    new_row
}
fn make_circulant_matrix(row: &[MyBool], rows: usize, cols: usize, shift: usize) -> DMatrix<MyBool> {
    let mut matrix: DMatrix<MyBool> = DMatrix::from_element(rows, cols, MyBool::from(false));
    for i in 0..rows {
        let new_row = shifted_row(&row[0..cols], i * shift);
        for j in 0..cols {
            matrix[(i, j)] = new_row[j];
        }
    }
    matrix
}

#[cfg(test)]
mod tests {
    use nalgebra::DMatrix;
    use crate::qc_mdpc::MyBool;

    #[test]
    fn test_make_circulant_matrix() {
        let row: Vec<MyBool> = [true, false, false, false, false, false, false, true, false, false].iter().map(|x| MyBool::from(*x)).collect();
        let matrix = super::make_circulant_matrix(&row, 7, 7, 1);
        let expected_generated_matrix = DMatrix::from_row_slice(7, 7, &[
            true, false, false, false, false, false, false,
            false, true, false, false, false, false, false,
            false, false, true, false, false, false, false,
            false, false, false, true, false, false, false,
            false, false, false, false, true, false, false,
            false, false, false, false, false, true, false,
            false, false, false, false, false, false, true,
        ].iter().map(|x| MyBool::from(*x)).collect::<Vec<MyBool>>());
        assert_eq!(matrix, expected_generated_matrix);
    }

    #[test]
    fn test_encode_decode_no_error() {
        let code = super::QcMdpc::init(2, 200, 30, 10);
        let public_key = code.get_public_key();
        let private_key = code.get_private_key();
        let encoded = super::QcMdpc::encode_data(&public_key, "This is my message".as_bytes());
        let decoded = super::QcMdpc::decode_data(&private_key, &encoded);
        assert_eq!(std::str::from_utf8(&decoded[0..18]).unwrap(), "This is my message");
    }

    #[test]
    fn test_encode_decode_on_error() {
        let code = super::QcMdpc::init(2, 200, 30, 10);
        let public_key = code.get_public_key();
        let private_key = code.get_private_key();
        let mut encoded = super::QcMdpc::encode_data(&public_key, "This is my message".as_bytes());
        **(encoded.get_mut((0, 0)).unwrap()) ^= true;
        let decoded = super::QcMdpc::decode_data(&private_key, &encoded);
        assert_eq!(std::str::from_utf8(&decoded[0..18]).unwrap(), "This is my message");
    }

    #[test]
    fn test_encode_decode_two_error() {
        let code = super::QcMdpc::init(2, 200, 30, 10);
        let public_key = code.get_public_key();
        let private_key = code.get_private_key();
        let mut encoded = super::QcMdpc::encode_data(&public_key, "This is my message".as_bytes());
        **(encoded.get_mut((0, 0)).unwrap()) ^= true;
        **(encoded.get_mut((0, 1)).unwrap()) ^= true;
        let decoded = super::QcMdpc::decode_data(&private_key, &encoded);
        assert_eq!(std::str::from_utf8(&decoded[0..18]).unwrap(), "This is my message");
    }
}