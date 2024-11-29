use num::integer::binomial;
use shamir_secret_sharing::num_bigint::BigUint;

pub fn nth_combination(n: usize, k: usize, mut index: BigUint) -> Vec<usize> {
    if k > n {
        panic!("k must be less than or equal to n");
    }
    if index >= binomial(BigUint::from(n), BigUint::from(k)) {
        panic!("index must be less than the number of combinations");
    }
    let mut combination = Vec::with_capacity(k);
    for i in 0..n {
        let binomial = binomial(BigUint::from(n - i - 1), BigUint::from(k - combination.len() - 1));
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

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use num::Zero;
    use shamir_secret_sharing::num_bigint::BigUint;

    #[test]
    fn test_nth_combination() {
        assert_eq!(super::nth_combination(5, 3, BigUint::zero()), vec![0, 1, 2]);
        assert_eq!(super::nth_combination(401, 7, BigUint::from_str("148166658473837").unwrap()), vec![34, 103, 186, 203, 230, 275, 323]);
    }
}
