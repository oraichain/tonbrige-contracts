pub fn is_expired(now: u64, timestamp: u64) -> bool {
    now > timestamp
}
