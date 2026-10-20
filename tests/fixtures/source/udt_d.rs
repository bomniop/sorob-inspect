#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, Env, String};

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Shape {
    Circle(u64),
    Rect(u32, u32),
    Unit,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Kind {
    A,
    B,
    C,
}

#[contract]
pub struct UdtD;

#[contractimpl]
impl UdtD {
    pub fn describe(env: Env, shape: Shape) -> String {
        let _ = shape;
        String::from_str(&env, "shape")
    }

    pub fn kind_code(kind: Kind) -> u32 {
        match kind {
            Kind::A => 0,
            Kind::B => 1,
            Kind::C => 2,
        }
    }
}
