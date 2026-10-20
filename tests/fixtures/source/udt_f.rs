#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype};

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Kind {
    A = 5,
    B = 1,
    C = 7,
}

#[contract]
pub struct UdtF;

#[contractimpl]
impl UdtF {
    pub fn kind_code(kind: Kind) -> u32 {
        match kind {
            Kind::A => 5,
            Kind::B => 1,
            Kind::C => 7,
        }
    }
}
