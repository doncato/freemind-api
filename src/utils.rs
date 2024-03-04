/// Some basic utilities
pub mod util {
    use rand::prelude::*;

    const BASE36_ALPHABET: &[u8; 36] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    /// Generates a random string in base36 of the provided length
    pub fn get_random_string(length: usize) -> String {
        let mut result: String = String::new();
        let mut rng = rand::thread_rng();
        for _ in 0..length {
            result.push(
                BASE36_ALPHABET[rng.gen_range(0..BASE36_ALPHABET.len())] as char
            );
        }
        result
    }

    #[cfg(test)]
    mod tests {
        use crate::utils::util;

        /// Verify that random strings are being generated
        #[test]
        fn test_random_generation() {
            let mut last_result: String = String::new();

            for _ in 0..5 {
                let new_result = util::get_random_string(18);

                assert_eq!(new_result.len(), 18);
                assert_ne!(new_result, last_result);

                last_result = new_result;
            }
        }
    }
}