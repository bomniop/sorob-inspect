#![no_std]

use soroban_sdk::{contract, contractevent, contractimpl, contracttype, symbol_short, Env, Symbol};

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Point {
    pub x: u32,
    pub y: u32,
}

#[contractevent(data_format = "single-value")]
pub struct MovedSv {
    #[topic]
    pub who: Symbol,
    pub dx: u32,
}

#[contractevent(data_format = "vec")]
pub struct MovedVec {
    #[topic]
    pub who: Symbol,
    pub dx: u32,
}

#[contractevent(data_format = "map")]
pub struct MovedMap {
    #[topic]
    pub who: Symbol,
    pub dx: u32,
}

#[contract]
pub struct EvFmt;

#[contractimpl]
impl EvFmt {
    pub fn go(env: Env, p: Point) -> u32 {
        MovedSv {
            who: symbol_short!("s"),
            dx: p.x,
        }
        .publish(&env);
        MovedVec {
            who: symbol_short!("v"),
            dx: p.x,
        }
        .publish(&env);
        MovedMap {
            who: symbol_short!("m"),
            dx: p.x,
        }
        .publish(&env);
        p.x + p.y
    }
}
