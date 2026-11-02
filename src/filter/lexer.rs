//! Splits a filter into tokens, keeping where each one starts and ends so
//! errors can point at it.

use super::FilterError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tok {
    /// A field name, keyword or unquoted value: `tcp.port`, `and`,
    /// `10.0.0.0/8`, `02:00:00:00:00:01`. Sets split `1..4` themselves.
    Word(String),
    /// A quoted string, with its escapes resolved.
    Str(String),
    /// Brackets, commas and operators: `(`, `==`, `&&`, `!` and so on.
    Sym(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub tok: Tok,
    pub start: usize,
    pub end: usize,
}

/// Longest first, so `===` isn't read as `==` followed by `=`.
const SYMBOLS: &[&str] = &[
    "===", "!==", "==", "!=", ">=", "<=", "&&", "||", "^^", "(", ")", "{", "}", ",", ">", "<", "~",
    "!", "&",
];

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b':' | b'/')
}

pub fn tokenize(text: &str) -> Result<Vec<Token>, FilterError> {
    let bytes = text.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        let start = i;
        if b == b'"' || (b == b'r' && bytes.get(i + 1) == Some(&b'"')) {
            let raw = b == b'r';
            let (s, end) = string(text, if raw { i + 1 } else { i }, raw)?;
            tokens.push(Token {
                tok: Tok::Str(s),
                start,
                end,
            });
            i = end;
            continue;
        }
        if is_word_byte(b) {
            while i < bytes.len() && is_word_byte(bytes[i]) {
                i += 1;
            }
            tokens.push(Token {
                tok: Tok::Word(text[start..i].to_string()),
                start,
                end: i,
            });
            continue;
        }
        if let Some(sym) = SYMBOLS.iter().find(|s| text[i..].starts_with(**s)) {
            i += sym.len();
            tokens.push(Token {
                tok: Tok::Sym(sym),
                start,
                end: i,
            });
            continue;
        }
        let c = text[i..].chars().next().expect("i is on a char boundary");
        let hint = match c {
            '=' => " (use == to compare)",
            '|' => " (use || for \"or\")",
            '\'' => " (strings take double quotes)",
            _ => "",
        };
        return Err(FilterError::new(
            format!("unexpected \"{c}\"{hint}"),
            start,
            start + c.len_utf8(),
        ));
    }
    Ok(tokens)
}

/// Reads the string whose opening quote is at `open`. Returns its value and
/// the position after the closing quote. Raw strings (`r"a\b"`) keep their
/// backslashes.
fn string(text: &str, open: usize, raw: bool) -> Result<(String, usize), FilterError> {
    let start = if raw { open - 1 } else { open };
    let unterminated = || FilterError::new("this string has no closing quote", start, text.len());
    let mut out = String::new();
    let mut chars = text[open + 1..].char_indices().peekable();
    while let Some((at, c)) = chars.next() {
        let pos = open + 1 + at;
        match c {
            '"' => return Ok((out, pos + 1)),
            '\\' if raw => {
                // A raw string can still hold a quote: r"a\"b" is a\"b.
                out.push('\\');
                if let Some(&(_, '"')) = chars.peek() {
                    out.push('"');
                    chars.next();
                }
            }
            '\\' => {
                let Some((_, e)) = chars.next() else {
                    return Err(unterminated());
                };
                match e {
                    'n' => out.push('\n'),
                    'r' => out.push('\r'),
                    't' => out.push('\t'),
                    'a' => out.push('\x07'),
                    'b' => out.push('\x08'),
                    'f' => out.push('\x0c'),
                    'v' => out.push('\x0b'),
                    '0'..='7' => {
                        let mut value = e.to_digit(8).unwrap();
                        for _ in 0..2 {
                            match chars.peek() {
                                Some(&(_, d @ '0'..='7')) => {
                                    value = value * 8 + d.to_digit(8).unwrap();
                                    chars.next();
                                }
                                _ => break,
                            }
                        }
                        push_byte(&mut out, value, pos)?;
                    }
                    'x' => {
                        let mut value = 0;
                        let mut digits = 0;
                        while digits < 2 {
                            match chars.peek() {
                                Some(&(_, d)) if d.is_ascii_hexdigit() => {
                                    value = value * 16 + d.to_digit(16).unwrap();
                                    digits += 1;
                                    chars.next();
                                }
                                _ => break,
                            }
                        }
                        if digits == 0 {
                            return Err(FilterError::new("\\x needs hex digits", pos, pos + 2));
                        }
                        push_byte(&mut out, value, pos)?;
                    }
                    'u' | 'U' => {
                        let len = if e == 'u' { 4 } else { 8 };
                        let digits: String = chars.clone().take(len).map(|(_, d)| d).collect();
                        let c = (digits.len() == len
                            && digits.chars().all(|d| d.is_ascii_hexdigit()))
                        .then(|| u32::from_str_radix(&digits, 16).ok())
                        .flatten()
                        .and_then(char::from_u32)
                        .ok_or_else(|| {
                            FilterError::new(
                                format!("\\{e} needs {len} hex digits naming a character"),
                                pos,
                                pos + 2,
                            )
                        })?;
                        out.push(c);
                        for _ in 0..len {
                            chars.next();
                        }
                    }
                    '\\' | '"' | '\'' => out.push(e),
                    // Wireshark rejects other escapes too. They mostly turn
                    // up in regular expressions.
                    other => {
                        return Err(FilterError::new(
                            format!(
                                "\\{other} isn't an escape; write \\\\{other}, or use a raw string such as r\"^api\\.\""
                            ),
                            pos,
                            pos + 1 + other.len_utf8(),
                        ));
                    }
                }
            }
            c => out.push(c),
        }
    }
    Err(unterminated())
}

/// Strings hold text, so a byte escape must be ASCII.
fn push_byte(out: &mut String, value: u32, pos: usize) -> Result<(), FilterError> {
    match u8::try_from(value) {
        Ok(b) if b.is_ascii() => {
            out.push(char::from(b));
            Ok(())
        }
        _ => Err(FilterError::new(
            "only ASCII can be written as an escape here",
            pos,
            pos + 1,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toks(text: &str) -> Vec<Tok> {
        tokenize(text).unwrap().into_iter().map(|t| t.tok).collect()
    }

    fn word(s: &str) -> Tok {
        Tok::Word(s.to_string())
    }

    #[test]
    fn splits_fields_operators_and_values() {
        assert_eq!(
            toks("tcp.port==443&&!(ip.src == 10.0.0.0/8)"),
            vec![
                word("tcp.port"),
                Tok::Sym("=="),
                word("443"),
                Tok::Sym("&&"),
                Tok::Sym("!"),
                Tok::Sym("("),
                word("ip.src"),
                Tok::Sym("=="),
                word("10.0.0.0/8"),
                Tok::Sym(")"),
            ]
        );
        assert_eq!(
            toks("a === b !== c in {1..4, fe80::1}"),
            vec![
                word("a"),
                Tok::Sym("==="),
                word("b"),
                Tok::Sym("!=="),
                word("c"),
                word("in"),
                Tok::Sym("{"),
                word("1..4"),
                Tok::Sym(","),
                word("fe80::1"),
                Tok::Sym("}"),
            ]
        );
    }

    #[test]
    fn strings_and_escapes() {
        assert_eq!(
            toks(r#"a == "x\"y\\z\x41\101\n" r"\d+\.""#),
            vec![
                word("a"),
                Tok::Sym("=="),
                Tok::Str("x\"y\\zAA\n".to_string()),
                Tok::Str(r"\d+\.".to_string()),
            ]
        );
        assert_eq!(toks(r#"r"a\"b""#), vec![Tok::Str(r#"a\"b"#.to_string())]);
        assert_eq!(toks(r#""é\'""#), vec![Tok::Str("é'".to_string())]);
        let err = tokenize(r#"a matches "^api\.""#).unwrap_err();
        assert!(err.message.contains("raw string"), "{}", err.message);
        assert!(tokenize(r#""\777""#).is_err());
    }

    #[test]
    fn errors_point_at_the_problem() {
        let err = tokenize("tcp.port = 80").unwrap_err();
        assert_eq!((err.start, err.end), (9, 10));
        assert!(err.message.contains("use =="), "{}", err.message);
        let err = tokenize("dns.qry.name == \"abc").unwrap_err();
        assert_eq!((err.start, err.end), (16, 20));
        assert!(tokenize("a == 'x'").is_err());
    }
}
