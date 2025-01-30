use num::One;
use num_bigint::BigUint;

pub fn nth_combination(n: usize, k: usize, mut index: BigUint) -> Vec<usize> {
    //println!("{} {} {}", n, k, index);
    //return vec![0; k];
    if k > n {
        panic!("k must be less than or equal to n");
    }
    if index >= binom(n, k) {
        panic!("index must be less than the number of combinations");
    }
    let mut combination = Vec::with_capacity(k);
    for i in 0..n {
        let binomial = binom(n - i - 1, k - combination.len() - 1);
        if index >= binomial {
            index -= binomial;
        } else {
            combination.push(i);
            if combination.len() == k {
                break;
            }
        }
    }
    combination
}

pub fn binom(n: usize, k: usize) -> BigUint {
    let mut res = BigUint::one();
    for i in 0..k {
        res = (res * BigUint::from(n - i)) /
            BigUint::from(i + 1);
    }
    res
}


#[cfg(test)]
mod tests {
    use num::{One, Zero};
    use num_bigint::BigUint;
    use std::str::FromStr;

    #[test]
    fn test_nth_combination() {
        assert_eq!(super::nth_combination(5, 3, BigUint::zero()), vec![0, 1, 2]);
        assert_eq!(super::nth_combination(5, 3, BigUint::one()), vec![0, 1, 3]);
        assert_eq!(
            super::nth_combination(5, 3, BigUint::from(3usize)),
            vec![0, 2, 3]
        );
        assert_eq!(
            super::nth_combination(401, 7, BigUint::from_str("148166658473837").unwrap()),
            vec![34, 103, 186, 203, 230, 275, 323]
        );
    }
}
