#![no_std]

use soroban_sdk::{contract, contractevent, contractimpl, contracttype, Address, Env, String, Vec};

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    pub owner: Address,
    pub fee: u32,
    pub active: bool,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Status {
    Pending,
    Active,
    Suspended,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventPayload {
    pub id: u64,
    pub label: String,
}

#[contractevent(data_format = "map")]
pub struct StatusEvent {
    #[topic]
    pub id: u64,
    pub status: u32,
}

#[contract]
pub struct UdtA;

#[contractimpl]
impl UdtA {
    pub fn init(env: Env, owner: Address, fee: u32) -> Config {
        let config = Config {
            owner,
            fee,
            active: false,
        };
        env.storage().persistent().set(&"config", &config);
        config
    }

    pub fn process(env: Env, config: Config, status: Status) -> Vec<String> {
        let _ = (config, status);
        Vec::new(&env)
    }

    pub fn get_config(env: Env) -> Config {
        env.storage().persistent().get(&"config").unwrap_or(Config {
            owner: env.current_contract_address(),
            fee: 0,
            active: false,
        })
    }

    pub fn get_status(env: Env) -> Status {
        env.storage()
            .persistent()
            .get(&"status")
            .unwrap_or(Status::Pending)
    }

    pub fn set_status(env: Env, status: Status) {
        env.storage().persistent().set(&"status", &status);
    }

    pub fn emit_status(env: Env, id: u64, code: u32) -> EventPayload {
        let payload = EventPayload {
            id,
            label: String::from_str(&env, "x"),
        };
        StatusEvent { id, status: code }.publish(&env);
        payload
    }
}
