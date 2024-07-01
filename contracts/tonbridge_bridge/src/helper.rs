pub fn is_expired(now: u64, timestamp: u64) -> bool {
    now > timestamp
}

mod tests {
    use crate::helper::is_expired;

    #[test]
    fn test_is_expired() {
        assert_eq!(is_expired(1, 2), false);
        assert_eq!(is_expired(2, 1), true);
        assert_eq!(is_expired(1, 1), false);
    }
}