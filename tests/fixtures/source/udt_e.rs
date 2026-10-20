#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype};

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Kind {
    A = 5,
    B = 1,
    C = 2,
}

#[contract]
pub struct UdtE;

#[contractimpl]
impl UdtE {
    pub fn kind_code(kind: Kind) -> u32 {
        match kind {
            Kind::A => 5,
            Kind::B => 1,
            Kind::C => 2,
        }
    }
}
