use std::cmp::max;
use nalgebra::DMatrix;
use crate::binary_matrix_operations::matrix_is_zero;
use crate::my_bool::MyBool;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificatelessQcMdpcPrivateKey {
    pub(super) parity_check_matrix: DMatrix<MyBool>,
    pub(super) expected_encoded_vector_size: usize,
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