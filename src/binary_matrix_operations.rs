use nalgebra::DMatrix;
use crate::my_bool::MyBool;

fn matrix_is_identity(matrix: &DMatrix<MyBool>) -> bool {
    if matrix.nrows() != matrix.ncols() {
        return false;
    }

    for i in 0..matrix.nrows() {
        for j in 0..matrix.ncols() {
            if i == j && !*matrix[(i, j)] {
                return false;
            } else if i != j && *matrix[(i, j)] {
                return false;
            }
        }
    }
    true
}

pub(crate) fn matrix_is_zero(matrix: &DMatrix<MyBool>) -> bool {
    for i in 0..matrix.nrows() {
        for j in 0..matrix.ncols() {
            if *matrix[(i, j)] {
                return false;
            }
        }
    }
    true
}

#[allow(dead_code)]
pub(crate) fn matrix_elements_sum(matrix: &DMatrix<MyBool>) -> usize {
    let mut sum = 0;
    for i in 0..matrix.nrows() {
        for j in 0..matrix.ncols() {
            if *matrix[(i, j)] {
                sum += 1;
            }
        }
    }
    sum
}

pub(crate) fn make_identity_matrix(size: usize) -> DMatrix<MyBool> {
    let mut matrix = DMatrix::from_element(size, size, MyBool::from(false));
    for i in 0..size {
        matrix[(i, i)] = MyBool::from(true);
    }
    matrix
}

pub(crate) fn try_inverse_matrix(matrix: &DMatrix<MyBool>) -> Option<DMatrix<MyBool>> {
    if matrix.nrows() != matrix.ncols() {
        return None;
    }
    let n = matrix.nrows();
    if matrix_is_identity(matrix) {
        return Some(matrix.clone())
    }

    let mut augmented = DMatrix::from_fn(n, 2 * n, |r, c| {
        if c < n {
            matrix[(r, c)] // Original matrix on the left
        } else {
            MyBool::from(r == c - n) // Identity matrix on the right
        }
    });

    // Perform Gaussian elimination
    for i in 0..n {
        // Check if the pivot is 1, if not, swap with a row below
        if !*augmented[(i, i)] {
            let mut swapped = false;
            for j in i + 1..n {
                if *augmented[(j, i)] {
                    for k in 0..2 * n {
                        augmented.swap((i, k), (j, k));
                    }
                    swapped = true;
                    break;
                }
            }
            if !swapped {
                // No valid pivot, matrix is not invertible
                return None;
            }
        }

        // Normalize the pivot row (pivot is always 1 in GF(2))
        for j in 0..n {
            if i != j && *augmented[(j, i)] {
                for k in 0..2 * n {
                    *augmented[(j, k)] ^= *augmented[(i, k)];
                }
            }
        }
    }

    // Extract the right half as the inverse matrix
    Some(augmented.view((0, n), (n, n)).into())
}

pub(crate) fn concat_horizontally_mat(original: &mut DMatrix<MyBool>, to_add: &DMatrix<MyBool>) {
    if original.nrows() != to_add.nrows() {
        panic!("The number of rows must be the same");
    }
    let original_ncols = original.ncols();
    original.resize_horizontally_mut(original_ncols + to_add.ncols(), MyBool::from(false));
    for column in 0..to_add.ncols() {
        for row in 0..to_add.nrows() {
            original[(row, column + original_ncols)] = to_add[(row, column)];
        }
    }
}

pub(crate) fn concat_vertically_mat(original: &mut DMatrix<MyBool>, to_add: &DMatrix<MyBool>) {
    if original.ncols() != to_add.ncols() {
        panic!("The number of columns must be the same");
    }
    let original_nrows = original.nrows();
    original.resize_vertically_mut(original_nrows + to_add.nrows(), MyBool::from(false));
    for row in 0..to_add.nrows() {
        for column in 0..to_add.ncols() {
            original[(row + original_nrows, column)] = to_add[(row, column)];
        }
    }
}

#[cfg(test)]
mod tests {
    use nalgebra::DMatrix;
    use crate::my_bool::MyBool;

    #[test]
    fn test_try_inverse_matrix() {
        let matrix = DMatrix::from_row_slice(3, 3, &[
            MyBool::from(true), MyBool::from(false), MyBool::from(false),
            MyBool::from(false), MyBool::from(true), MyBool::from(false),
            MyBool::from(false), MyBool::from(false), MyBool::from(true),
        ]);
        let inverse = super::try_inverse_matrix(&matrix).unwrap();
        assert_eq!(matrix, inverse);

        let matrix = DMatrix::from_row_slice(2, 2, &[
            MyBool::from(false), MyBool::from(true),
            MyBool::from(true), MyBool::from(false),
        ]);
        let inverse = super::try_inverse_matrix(&matrix).unwrap();
        assert_eq!(matrix, inverse);
    }
}