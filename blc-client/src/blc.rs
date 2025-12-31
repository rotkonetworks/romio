//! Binary Lambda Calculus (BLC) parser and encoder
//!
//! BLC encoding (bits, MSB first):
//!   00 = λ (abstraction)
//!   01 = application
//!   1^n 0 = de Bruijn variable n (n ones followed by zero)

use std::fmt;

/// BLC term representation
#[derive(Debug, Clone, PartialEq)]
pub enum Term {
    /// Variable with de Bruijn index
    Var(usize),
    /// Lambda abstraction
    Abs(Box<Term>),
    /// Application
    App(Box<Term>, Box<Term>),
}

impl fmt::Display for Term {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Term::Var(i) => write!(f, "{}", i),
            Term::Abs(body) => write!(f, "λ.{}", body),
            Term::App(func, arg) => write!(f, "({} {})", func, arg),
        }
    }
}

/// Bit reader for parsing BLC
struct BitReader<'a> {
    data: &'a [u8],
    byte_pos: usize,
    bit_pos: u8,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            byte_pos: 0,
            bit_pos: 0,
        }
    }

    fn read_bit(&mut self) -> Option<bool> {
        if self.byte_pos >= self.data.len() {
            return None;
        }
        let bit = (self.data[self.byte_pos] >> (7 - self.bit_pos)) & 1;
        self.bit_pos += 1;
        if self.bit_pos == 8 {
            self.bit_pos = 0;
            self.byte_pos += 1;
        }
        Some(bit == 1)
    }

    #[allow(dead_code)]
    fn bits_read(&self) -> usize {
        self.byte_pos * 8 + self.bit_pos as usize
    }
}

/// Bit writer for encoding BLC
struct BitWriter {
    data: Vec<u8>,
    bit_pos: u8,
}

impl BitWriter {
    fn new() -> Self {
        Self {
            data: vec![0],
            bit_pos: 0,
        }
    }

    fn write_bit(&mut self, bit: bool) {
        if bit {
            let idx = self.data.len() - 1;
            self.data[idx] |= 1 << (7 - self.bit_pos);
        }
        self.bit_pos += 1;
        if self.bit_pos == 8 {
            self.bit_pos = 0;
            self.data.push(0);
        }
    }

    fn finish(mut self) -> Vec<u8> {
        // remove trailing zero byte if we're byte-aligned
        if self.bit_pos == 0 && !self.data.is_empty() {
            self.data.pop();
        }
        self.data
    }
}

/// Parse a BLC term from binary data
pub fn parse_blc(data: &[u8]) -> Result<Term, String> {
    let mut reader = BitReader::new(data);
    parse_term(&mut reader)
}

fn parse_term(reader: &mut BitReader) -> Result<Term, String> {
    let b1 = reader.read_bit().ok_or("unexpected end of input")?;

    if !b1 {
        let b2 = reader.read_bit().ok_or("unexpected end of input")?;
        if !b2 {
            // 00 = abstraction
            let body = parse_term(reader)?;
            Ok(Term::Abs(Box::new(body)))
        } else {
            // 01 = application
            let func = parse_term(reader)?;
            let arg = parse_term(reader)?;
            Ok(Term::App(Box::new(func), Box::new(arg)))
        }
    } else {
        // 1...0 = variable
        let mut index = 0;
        while reader.read_bit().ok_or("unexpected end of input")? {
            index += 1;
        }
        Ok(Term::Var(index))
    }
}

/// Encode a BLC term to binary
pub fn encode_blc(term: &Term) -> Vec<u8> {
    let mut writer = BitWriter::new();
    encode_term(&mut writer, term);
    writer.finish()
}

fn encode_term(writer: &mut BitWriter, term: &Term) {
    match term {
        Term::Abs(body) => {
            writer.write_bit(false); // 0
            writer.write_bit(false); // 0
            encode_term(writer, body);
        }
        Term::App(func, arg) => {
            writer.write_bit(false); // 0
            writer.write_bit(true);  // 1
            encode_term(writer, func);
            encode_term(writer, arg);
        }
        Term::Var(index) => {
            for _ in 0..=*index {
                writer.write_bit(true); // 1
            }
            writer.write_bit(false); // 0
        }
    }
}

/// Parse BLC from text notation (λ syntax or hex)
pub fn parse_blc_text(text: &str) -> Result<Term, String> {
    let text = text.trim();

    // try hex first
    if text.starts_with("0x") || text.chars().all(|c| c.is_ascii_hexdigit()) {
        let hex_str = text.strip_prefix("0x").unwrap_or(text);
        let bytes = hex::decode(hex_str).map_err(|e| format!("invalid hex: {}", e))?;
        return parse_blc(&bytes);
    }

    // parse lambda notation
    parse_lambda_text(text)
}

fn parse_lambda_text(text: &str) -> Result<Term, String> {
    let mut chars = text.chars().peekable();
    parse_lambda_term(&mut chars)
}

fn parse_lambda_term(chars: &mut std::iter::Peekable<std::str::Chars>) -> Result<Term, String> {
    skip_whitespace(chars);

    match chars.peek() {
        Some('λ') | Some('\\') => {
            chars.next();
            skip_whitespace(chars);
            // skip variable name if present
            while chars.peek().map(|c| c.is_alphanumeric()).unwrap_or(false) {
                chars.next();
            }
            skip_whitespace(chars);
            if chars.peek() == Some(&'.') {
                chars.next();
            }
            let body = parse_lambda_term(chars)?;
            Ok(Term::Abs(Box::new(body)))
        }
        Some('(') => {
            chars.next();
            let func = parse_lambda_term(chars)?;
            skip_whitespace(chars);
            let arg = parse_lambda_term(chars)?;
            skip_whitespace(chars);
            if chars.next() != Some(')') {
                return Err("expected ')'".to_string());
            }
            Ok(Term::App(Box::new(func), Box::new(arg)))
        }
        Some(c) if c.is_ascii_digit() => {
            let mut num = String::new();
            while chars.peek().map(|c| c.is_ascii_digit()).unwrap_or(false) {
                num.push(chars.next().unwrap());
            }
            let index: usize = num.parse().map_err(|_| "invalid number")?;
            Ok(Term::Var(index))
        }
        Some(c) => Err(format!("unexpected character: {}", c)),
        None => Err("unexpected end of input".to_string()),
    }
}

fn skip_whitespace(chars: &mut std::iter::Peekable<std::str::Chars>) {
    while chars.peek().map(|c| c.is_whitespace()).unwrap_or(false) {
        chars.next();
    }
}

/// Common BLC terms
pub mod prelude {
    use super::Term;

    /// Identity: λx.x = 00 10
    pub fn identity() -> Term {
        Term::Abs(Box::new(Term::Var(0)))
    }

    /// Church TRUE: λx.λy.x = 00 00 110
    pub fn church_true() -> Term {
        Term::Abs(Box::new(Term::Abs(Box::new(Term::Var(1)))))
    }

    /// Church FALSE: λx.λy.y = 00 00 10
    pub fn church_false() -> Term {
        Term::Abs(Box::new(Term::Abs(Box::new(Term::Var(0)))))
    }

    /// Church numeral 0: λf.λx.x
    pub fn church_zero() -> Term {
        church_false()
    }

    /// Church numeral 1: λf.λx.f x
    pub fn church_one() -> Term {
        Term::Abs(Box::new(Term::Abs(Box::new(
            Term::App(Box::new(Term::Var(1)), Box::new(Term::Var(0)))
        ))))
    }

    /// S combinator: λx.λy.λz.xz(yz)
    pub fn s_combinator() -> Term {
        Term::Abs(Box::new(Term::Abs(Box::new(Term::Abs(Box::new(
            Term::App(
                Box::new(Term::App(Box::new(Term::Var(2)), Box::new(Term::Var(0)))),
                Box::new(Term::App(Box::new(Term::Var(1)), Box::new(Term::Var(0))))
            )
        ))))))
    }

    /// K combinator: λx.λy.x (same as TRUE)
    pub fn k_combinator() -> Term {
        church_true()
    }

    /// I combinator: λx.x (same as identity)
    pub fn i_combinator() -> Term {
        identity()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity() {
        let id = prelude::identity();
        let encoded = encode_blc(&id);
        assert_eq!(encoded, vec![0x20]); // 00 10 0000 = 0x20

        let decoded = parse_blc(&encoded).unwrap();
        assert_eq!(decoded, id);
    }

    #[test]
    fn test_church_true() {
        let t = prelude::church_true();
        let encoded = encode_blc(&t);
        assert_eq!(encoded, vec![0x0C]); // 00 00 110 0 = 0x0C
    }

    #[test]
    fn test_church_false() {
        let f = prelude::church_false();
        let encoded = encode_blc(&f);
        assert_eq!(encoded, vec![0x08]); // 00 00 10 00 = 0x08
    }

    #[test]
    fn test_application() {
        // (λx.x)(λx.x) = 01 0010 0010
        let app = Term::App(
            Box::new(prelude::identity()),
            Box::new(prelude::identity())
        );
        let encoded = encode_blc(&app);
        assert_eq!(encoded, vec![0x48, 0x80]); // 0100 1000 1000 0000
    }

    #[test]
    fn test_parse_hex() {
        let term = parse_blc_text("0x20").unwrap();
        assert_eq!(term, prelude::identity());
    }

    #[test]
    fn test_parse_lambda() {
        let term = parse_blc_text("λ.0").unwrap();
        assert_eq!(term, prelude::identity());
    }
}
