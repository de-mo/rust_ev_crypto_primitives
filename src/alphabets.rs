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

//! Implementation the algorithms for strings and alphabets

use lazy_static::lazy_static;

lazy_static! {
/// Static struct of the alphabet latin according to §4.2 of the specifications
pub static ref ALPHABET_LATIN: Alphabet = Alphabet::new(ALPHABET_LATIN_CONTENT);
/// Static struct of the user friendly alphabet according to §4.1 of the specifications
pub static ref ALPHABET_USER_FRIENDLY: Alphabet = Alphabet::new(ALPHABET_USER_FRIENDLY_CONTENT);}

const ALPHABET_LATIN_CONTENT: &str = "\u{23}\u{20}\u{27}\u{28}\u{29}\u{2C}\u{2D}\u{2E}\u{2F}\u{30}\
\u{31}\u{32}\u{33}\u{34}\u{35}\u{36}\u{37}\u{38}\u{39}\u{41}\
\u{42}\u{43}\u{44}\u{45}\u{46}\u{47}\u{48}\u{49}\u{4a}\u{4b}\
\u{4c}\u{4d}\u{4e}\u{4f}\u{50}\u{51}\u{52}\u{53}\u{54}\u{55}\
\u{56}\u{57}\u{58}\u{59}\u{5a}\u{61}\u{62}\u{63}\u{64}\u{65}\
\u{66}\u{67}\u{68}\u{69}\u{6a}\u{6b}\u{6c}\u{6d}\u{6e}\u{6f}\
\u{70}\u{71}\u{72}\u{73}\u{74}\u{75}\u{76}\u{77}\u{78}\u{79}\
\u{7a}\u{a2}\u{160}\u{161}\u{17d}\u{17e}\u{152}\u{153}\u{178}\u{c0}\
\u{c1}\u{c2}\u{c3}\u{c4}\u{c5}\u{c6}\u{c7}\u{c8}\u{c9}\u{ca}\
\u{cb}\u{cc}\u{cd}\u{ce}\u{cf}\u{d0}\u{d1}\u{d2}\u{d3}\u{d4}\
\u{d5}\u{d6}\u{d8}\u{d9}\u{da}\u{db}\u{dc}\u{dd}\u{de}\u{df}\
\u{e0}\u{e1}\u{e2}\u{e3}\u{e4}\u{e5}\u{e6}\u{e7}\u{e8}\u{e9}\
\u{ea}\u{eb}\u{ec}\u{ed}\u{ee}\u{ef}\u{f0}\u{f1}\u{f2}\u{f3}\
\u{f4}\u{f5}\u{f6}\u{f8}\u{f9}\u{fa}\u{fb}\u{fc}\u{fd}\u{fe}\
\u{ff}";

const ALPHABET_USER_FRIENDLY_CONTENT: &str = "abcdefghijkmnpqrstuvwxyz23456789";

/// Alphabet
pub struct Alphabet(&'static str);

impl Alphabet {
    pub fn new(chars: &'static str) -> Self {
        Self(chars)
    }

    /// Size of the alphabet
    pub fn size(&self) -> usize {
        self.0.chars().count()
    }

    /// Character at position `pos` of the alphabet
    pub fn character_at_pos(&self, pos: usize) -> Option<char> {
        self.0.chars().nth(pos)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_latin() {
        assert_eq!(ALPHABET_LATIN.size(), 141);
        assert_eq!(ALPHABET_LATIN.character_at_pos(14), Some('5'));
        assert_eq!(ALPHABET_LATIN.character_at_pos(28), Some('J'));
        assert_eq!(ALPHABET_LATIN.character_at_pos(125), Some('ï'));
    }
}
