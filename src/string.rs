// Copyright © 2023 Denis Morel

// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option) any
// later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details.
//
// You should have received a copy of the GNU General Public License and
// a copy of the GNU General Public License along with this program. If not, see
// <https://www.gnu.org/licenses/>.

//! Implementation the algorithms for strings

use std::cmp::min;

pub fn truncate(s: &str, l: usize) -> String {
    let u = s.len();
    let m = min(u, l);
    s.chars().take(m).collect()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_truncate() {
        let s = "1234567890";
        assert_eq!(truncate(s, 2), "12".to_string());
        assert_eq!(truncate(s, 0), String::new());
        assert_eq!(truncate(s, 5), "12345".to_string());
        assert_eq!(truncate(s, 10), "1234567890".to_string());
        assert_eq!(truncate(s, 11), "1234567890".to_string());
    }
}
