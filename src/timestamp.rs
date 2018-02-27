use types::U5;

/// seconds-since-1970 (35 bits, big-endian)
struct Timestamp;

impl Timestamp {
    /// decode timestamp from u5 vector
    fn decode(data: &Vec<U5>) -> u64 {
        data.iter().take(7).fold(0, |a, b| a * 32u64 + *b as u64)
    }
    /// encode timestamp
    fn encode(timestamp: u64) -> Vec<U5> {
        let mut acc: Vec<U5> = Vec::new();
        let mut time_acc = timestamp;
        // 35 bits, big-endian
        while acc.len() < 7 {
            acc.push((time_acc % 32) as U5);
            time_acc /= 32;
        }
        acc.reverse();
        acc
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn timestamp() {
        let data: Vec<U5> = vec![1, 12, 18, 31, 28, 25, 2];
        let timestamp = 1496314658;

        assert_eq!(Timestamp::decode(&data), timestamp);
        assert!(data.eq(&Timestamp::encode(timestamp)));
    }
}
