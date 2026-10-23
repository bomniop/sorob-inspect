#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, String};

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    pub owner: Address,
    pub fee: u32,
    pub active: bool,
    pub count: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Status {
    Active,
    Inactive,
    Suspended,
}

#[contract]
pub struct UdtB;

#[contractimpl]
impl UdtB {
    pub fn get_config(env: Env) -> Config {
        env.storage().persistent().get(&"config").unwrap_or(Config {
            owner: env.current_contract_address(),
            fee: 0,
            active: false,
            count: 0,
        })
    }

    pub fn get_status(env: Env) -> Status {
        env.storage()
            .persistent()
            .get(&"status")
            .unwrap_or(Status::Active)
    }

    pub fn set_config(env: Env, config: Config) {
        env.storage().persistent().set(&"config", &config);
    }

    pub fn set_status(env: Env, s: Status) {
        env.storage().persistent().set(&"status", &s);
    }
}
