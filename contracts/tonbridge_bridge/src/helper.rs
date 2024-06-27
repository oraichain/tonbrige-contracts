use cosmwasm_std::Env;

pub fn is_expired(env: &Env, timestamp: u64) -> bool {
    env.block.time.seconds() > timestamp
}
