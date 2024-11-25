use std::fmt::Display;
use std::ops::{Add, AddAssign, Deref, DerefMut, Mul, MulAssign};
use num::{One, Zero};


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MyBool(bool);
impl Deref for MyBool {
    type Target = bool;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for MyBool {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Display for MyBool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if **self {
            write!(f, "1")
        } else {
            write!(f, "0")
        }
    }
}

impl From<bool> for MyBool {
    fn from(b: bool) -> Self {
        Self(b)
    }
}

impl MulAssign for MyBool {
    fn mul_assign(&mut self, rhs: Self) {
        *self = MyBool::from(**self && *rhs);
    }
}

impl Mul for MyBool {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        MyBool::from(*self && *rhs)
    }
}

impl Add<Self> for MyBool {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        MyBool::from(*self ^ *rhs)
    }
}

impl Zero for MyBool {
    fn zero() -> Self {
        MyBool::from(false)
    }

    fn is_zero(&self) -> bool {
        self.0 == false
    }
}

impl One for MyBool {
    fn one() -> Self {
        MyBool::from(true)
    }
}

impl AddAssign<Self> for MyBool {
    fn add_assign(&mut self, rhs: Self) {
        *self = MyBool::from(**self ^ *rhs);
    }
}