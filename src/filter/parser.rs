//! Recursive descent from tokens to an expression. Fields are looked up and
//! values read as their field's type here, so a bad filter fails before any
//! packet is read.
//!
//! ```text
//! or      = xor { ("||" | "or") xor }
//! xor     = and { ("^^" | "xor") and }
//! and     = unary { ("&&" | "and") unary }
//! unary   = ("!" | "not") unary | "(" or ")" | test
//! test    = operand [ op value | op operand | ["not"] "in" set ]
//! operand = field [ "&" number ] | function "(" field ")"
//! set     = "{" item { "," item } "}"      item = value [ ".." value ]
//! ```

use std::net::IpAddr;

use regex_lite::RegexBuilder;

use super::eval::{Cmp, Expr, Literal, Operand, Rhs, SetItem, Value};
use super::fields::{self, Kind};
use super::lexer::{self, Tok, Token};
use super::{Field, FilterError, FindingField};
use crate::diagnose::{Category, Severity};

const FUNCTIONS: &[&str] = &["lower", "upper", "len", "count"];

/// Returns the expression and every field it uses.
pub fn parse(text: &str) -> Result<(Expr, Vec<Field>), FilterError> {
    let tokens = lexer::tokenize(text)?;
    if tokens.is_empty() {
        return Err(FilterError::new("the filter is empty", 0, 0));
    }
    let mut p = Parser {
        tokens,
        pos: 0,
        end: text.len(),
        fields: Vec::new(),
    };
    let expr = p.or()?;
    if let Some(t) = p.peek() {
        return Err(unexpected(t));
    }
    Ok((expr, p.fields))
}

/// The left side of a test, with what it holds.
struct Lhs {
    op: Operand,
    kind: Kind,
    /// The field inside, for messages and value names.
    field: Field,
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    end: usize,
    fields: Vec<Field>,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn peek_tok(&self, ahead: usize) -> Option<&Tok> {
        self.tokens.get(self.pos + ahead).map(|t| &t.tok)
    }

    /// Takes the next token if it is one of `syms` or `words`.
    fn eat(&mut self, syms: &[&str], words: &[&str]) -> bool {
        let found = match self.peek_tok(0) {
            Some(Tok::Sym(s)) => syms.contains(s),
            Some(Tok::Word(w)) => words.contains(&w.as_str()),
            _ => false,
        };
        if found {
            self.pos += 1;
        }
        found
    }

    /// The next token, or an error saying what was expected there.
    fn take(&mut self, wanted: &str) -> Result<Token, FilterError> {
        match self.tokens.get(self.pos) {
            Some(t) => {
                self.pos += 1;
                Ok(t.clone())
            }
            None => Err(FilterError::new(
                format!("the filter ends where {wanted} should be"),
                self.end,
                self.end,
            )),
        }
    }

    fn or(&mut self) -> Result<Expr, FilterError> {
        let mut left = self.xor()?;
        while self.eat(&["||"], &["or"]) {
            left = Expr::Or(Box::new(left), Box::new(self.xor()?));
        }
        Ok(left)
    }

    fn xor(&mut self) -> Result<Expr, FilterError> {
        let mut left = self.and()?;
        while self.eat(&["^^"], &["xor"]) {
            left = Expr::Xor(Box::new(left), Box::new(self.and()?));
        }
        Ok(left)
    }

    fn and(&mut self) -> Result<Expr, FilterError> {
        let mut left = self.unary()?;
        while self.eat(&["&&"], &["and"]) {
            left = Expr::And(Box::new(left), Box::new(self.unary()?));
        }
        Ok(left)
    }

    fn unary(&mut self) -> Result<Expr, FilterError> {
        if self.eat(&["!"], &["not"]) {
            return Ok(Expr::Not(Box::new(self.unary()?)));
        }
        if let Some(Tok::Sym("(")) = self.peek_tok(0) {
            let open = self.take("(")?;
            let expr = self.or()?;
            return match self.take("a \")\"") {
                Ok(Token {
                    tok: Tok::Sym(")"), ..
                }) => Ok(expr),
                Ok(other) => Err(unexpected(&other)),
                Err(_) => Err(FilterError::new(
                    "this \"(\" is never closed",
                    open.start,
                    open.end,
                )),
            };
        }
        self.test()
    }

    fn test(&mut self) -> Result<Expr, FilterError> {
        let lhs = self.operand()?;
        let cmp = match self.peek_tok(0) {
            Some(Tok::Sym(s)) => match *s {
                "==" => Some(Cmp::AnyEq),
                "!=" => Some(Cmp::AllNe),
                "===" => Some(Cmp::AllEq),
                "!==" => Some(Cmp::AnyNe),
                ">" => Some(Cmp::Gt),
                ">=" => Some(Cmp::Ge),
                "<" => Some(Cmp::Lt),
                "<=" => Some(Cmp::Le),
                "~" => Some(Cmp::Matches),
                _ => None,
            },
            Some(Tok::Word(w)) => match w.as_str() {
                "eq" | "any_eq" => Some(Cmp::AnyEq),
                "ne" | "all_ne" => Some(Cmp::AllNe),
                "all_eq" => Some(Cmp::AllEq),
                "any_ne" => Some(Cmp::AnyNe),
                "gt" => Some(Cmp::Gt),
                "ge" => Some(Cmp::Ge),
                "lt" => Some(Cmp::Lt),
                "le" => Some(Cmp::Le),
                "contains" => Some(Cmp::Contains),
                "matches" => Some(Cmp::Matches),
                _ => None,
            },
            None => None,
            Some(Tok::Str(_)) => None,
        };
        if let Some(cmp) = cmp {
            let op = self.take("an operator")?;
            return self.comparison(lhs, cmp, &op);
        }
        if self.eat(&[], &["in"]) {
            return self.set(lhs, false);
        }
        if matches!(self.peek_tok(0), Some(Tok::Word(w)) if w == "not")
            && matches!(self.peek_tok(1), Some(Tok::Word(w)) if w == "in")
        {
            self.pos += 2;
            return self.set(lhs, true);
        }
        match lhs.op {
            Operand::Field(field) => Ok(Expr::Exists(field)),
            Operand::Mask(..) => Ok(Expr::Nonzero(lhs.op)),
            _ => {
                let at = self.tokens[self.pos - 1].end;
                Err(FilterError::new(
                    "compare this with something, as in len(dns.qry.name) > 30",
                    at,
                    at,
                ))
            }
        }
    }

    fn operand(&mut self) -> Result<Lhs, FilterError> {
        let tok = self.take("a field name")?;
        let Tok::Word(word) = &tok.tok else {
            return Err(match tok.tok {
                Tok::Str(_) => FilterError::new(
                    "a test starts with a field name, as in tcp.port == 80",
                    tok.start,
                    tok.end,
                ),
                _ => unexpected(&tok),
            });
        };
        if FUNCTIONS.contains(&word.as_str()) && matches!(self.peek_tok(0), Some(Tok::Sym("("))) {
            self.pos += 1;
            let arg = self.take("a field name")?;
            let field = self.field(&arg)?;
            match self.take("a \")\"")? {
                Token {
                    tok: Tok::Sym(")"), ..
                } => {}
                other => return Err(unexpected(&other)),
            }
            let kind = field.kind();
            let wrong = |wants: &str| {
                FilterError::new(
                    format!(
                        "{word}() takes {wants}; {} is a {}",
                        field.name(),
                        kind.describe()
                    ),
                    arg.start,
                    arg.end,
                )
            };
            let (op, kind) = match word.as_str() {
                "lower" | "upper" if kind != Kind::Str => return Err(wrong("a string field")),
                "lower" => (Operand::Lower(field), Kind::Str),
                "upper" => (Operand::Upper(field), Kind::Str),
                "len" if !matches!(kind, Kind::Str | Kind::Bytes | Kind::Protocol) => {
                    return Err(wrong("a string or bytes field"));
                }
                "len" => (Operand::Len(field), Kind::UInt),
                _ => (Operand::Count(field), Kind::UInt),
            };
            return Ok(Lhs { op, kind, field });
        }
        let field = self.field(&tok)?;
        if self.eat(&["&"], &[]) {
            let mask = self.take("a number")?;
            if field.kind() != Kind::UInt {
                return Err(FilterError::new(
                    format!(
                        "& needs a number field; {} is a {}",
                        field.name(),
                        field.kind().describe()
                    ),
                    mask.start,
                    mask.end,
                ));
            }
            let value = match &mask.tok {
                Tok::Word(w) => parse_uint(w),
                _ => None,
            }
            .ok_or_else(|| FilterError::new("& takes a number, like 0x02", mask.start, mask.end))?;
            return Ok(Lhs {
                op: Operand::Mask(field, value),
                kind: Kind::UInt,
                field,
            });
        }
        Ok(Lhs {
            op: Operand::Field(field),
            kind: field.kind(),
            field,
        })
    }

    fn field(&mut self, tok: &Token) -> Result<Field, FilterError> {
        let Tok::Word(name) = &tok.tok else {
            return Err(unexpected(tok));
        };
        let field = fields::lookup(name)
            .map(|(f, _)| Field::Packet(f))
            .or_else(|| FindingField::lookup(name).map(Field::Finding))
            .ok_or_else(|| unknown_field(name, tok))?;
        self.fields.push(field);
        Ok(field)
    }

    /// Whether the next tokens are a field (or a function of one) rather
    /// than a value, as in `ip.src == ip.dst`.
    fn field_next(&self) -> bool {
        match self.peek_tok(0) {
            Some(Tok::Word(w)) => {
                fields::lookup(w).is_some()
                    || FindingField::lookup(w).is_some()
                    || (FUNCTIONS.contains(&w.as_str())
                        && matches!(self.peek_tok(1), Some(Tok::Sym("("))))
            }
            _ => false,
        }
    }

    fn comparison(&mut self, lhs: Lhs, cmp: Cmp, op: &Token) -> Result<Expr, FilterError> {
        let name = lhs.field.name();
        let fail = |msg: String| Err(FilterError::new(msg, op.start, op.end));
        if lhs.kind == Kind::Marker {
            return fail(format!(
                "{name} has no value to compare; test it on its own (\"{name}\" or \"!{name}\")"
            ));
        }
        let text_like = matches!(lhs.kind, Kind::Str | Kind::Bytes | Kind::Protocol);
        match cmp {
            Cmp::Contains | Cmp::Matches if !text_like => {
                return fail(format!(
                    "{name} is a {}; contains and matches work on strings and bytes",
                    lhs.kind.describe()
                ));
            }
            Cmp::Gt | Cmp::Ge | Cmp::Lt | Cmp::Le if lhs.kind == Kind::Protocol => {
                return fail(format!("{name} is a protocol and can't be ordered"));
            }
            _ => {}
        }

        if cmp != Cmp::Matches && self.field_next() {
            let start = self.pos;
            let rhs = self.operand()?;
            let same = rhs.kind == lhs.kind
                || matches!(
                    (lhs.kind, rhs.kind),
                    (Kind::Bytes | Kind::Protocol, Kind::Bytes | Kind::Protocol)
                );
            if same {
                return Ok(Expr::Compare(lhs.op, cmp, Rhs::Operand(rhs.op)));
            }
            // A value that happens to be a field name, as in
            // finding.category == dns.
            let word = self.tokens[start].clone();
            if self.pos == start + 1
                && let Ok(lit) = self.literal(&lhs, &word, cmp == Cmp::Contains)
            {
                self.fields.pop();
                return Ok(Expr::Compare(lhs.op, cmp, Rhs::Literal(lit)));
            }
            return fail(format!(
                "can't compare {name} ({}) with {} ({})",
                lhs.kind.describe(),
                rhs.field.name(),
                rhs.kind.describe()
            ));
        }

        let tok = self.take("a value")?;
        if cmp == Cmp::Matches {
            let pattern = value_text(&tok)?;
            let re = RegexBuilder::new(pattern)
                .case_insensitive(true)
                .build()
                .map_err(|e| {
                    FilterError::new(format!("bad regular expression: {e}"), tok.start, tok.end)
                })?;
            return Ok(Expr::Compare(lhs.op, cmp, Rhs::Regex(re)));
        }
        let lit = self.literal(&lhs, &tok, cmp == Cmp::Contains)?;
        Ok(Expr::Compare(lhs.op, cmp, Rhs::Literal(lit)))
    }

    fn set(&mut self, lhs: Lhs, negated: bool) -> Result<Expr, FilterError> {
        let name = lhs.field.name();
        let open = self.take("a \"{\"")?;
        if open.tok != Tok::Sym("{") {
            return Err(FilterError::new(
                "\"in\" takes a set, as in tcp.port in {80, 443, 8000..8080}",
                open.start,
                open.end,
            ));
        }
        if matches!(lhs.kind, Kind::Marker | Kind::Protocol) {
            return Err(FilterError::new(
                format!("{name} has no value to look up in a set"),
                open.start,
                open.end,
            ));
        }
        let mut set = Vec::new();
        loop {
            let tok = self.take("a value")?;
            if tok.tok == Tok::Sym("}") && set.is_empty() {
                return Err(FilterError::new("the set is empty", open.start, tok.end));
            }
            let item = match &tok.tok {
                Tok::Word(w) if w.contains("..") && !w.starts_with("..") => {
                    let (lo, hi) = w.split_once("..").expect("checked");
                    let split = tok.start + lo.len();
                    let lo = Token {
                        tok: Tok::Word(lo.to_string()),
                        start: tok.start,
                        end: split,
                    };
                    let hi = Token {
                        tok: Tok::Word(hi.to_string()),
                        start: split + 2,
                        end: tok.end,
                    };
                    self.range(&lhs, &lo, &hi)?
                }
                _ => {
                    let lo = self.literal(&lhs, &tok, false)?;
                    match self.peek_tok(0).cloned() {
                        Some(Tok::Word(w)) if w == ".." => {
                            self.pos += 1;
                            let hi = self.take("the end of the range")?;
                            self.range(&lhs, &tok, &hi)?
                        }
                        Some(Tok::Word(w)) if w.starts_with("..") => {
                            let next = self.take("the end of the range")?;
                            let hi = Token {
                                tok: Tok::Word(w[2..].to_string()),
                                start: next.start + 2,
                                end: next.end,
                            };
                            self.range(&lhs, &tok, &hi)?
                        }
                        _ => SetItem::One(lo),
                    }
                }
            };
            set.push(item);
            match self.take("a \"}\"") {
                Ok(Token {
                    tok: Tok::Sym(","), ..
                }) => {}
                Ok(Token {
                    tok: Tok::Sym("}"), ..
                }) => break,
                Ok(other) => {
                    return Err(FilterError::new(
                        "set members are separated by commas, as in {80, 443}",
                        other.start,
                        other.end,
                    ));
                }
                Err(_) => {
                    return Err(FilterError::new(
                        "this \"{\" is never closed",
                        open.start,
                        open.end,
                    ));
                }
            }
        }
        Ok(Expr::In {
            lhs: lhs.op,
            set,
            negated,
        })
    }

    fn range(&self, lhs: &Lhs, lo: &Token, hi: &Token) -> Result<SetItem, FilterError> {
        if matches!(lhs.kind, Kind::Bool | Kind::Bytes | Kind::Ether) {
            return Err(FilterError::new(
                format!("{} can't take a range", lhs.field.name()),
                lo.start,
                hi.end,
            ));
        }
        Ok(SetItem::Range(
            self.literal(lhs, lo, false)?,
            self.literal(lhs, hi, false)?,
        ))
    }

    /// Reads `tok` as a value of the left side's type. `contains` on a
    /// string field takes any text.
    fn literal(&self, lhs: &Lhs, tok: &Token, contains: bool) -> Result<Literal, FilterError> {
        let text = value_text(tok)?;
        let quoted = matches!(tok.tok, Tok::Str(_));
        let name = lhs.field.name();
        let err = |msg: String| FilterError::new(msg, tok.start, tok.end);
        let value = match lhs.kind {
            Kind::Bool => match text.to_ascii_lowercase().as_str() {
                "1" | "true" => Value::Bool(true),
                "0" | "false" => Value::Bool(false),
                _ => return Err(err(format!("{name} is true or false: write 1 or 0"))),
            },
            Kind::UInt => {
                let names = match lhs.op {
                    Operand::Field(Field::Packet(f)) => fields::value_names(f),
                    _ => &[],
                };
                let named = names
                    .iter()
                    .find(|(_, n)| n.eq_ignore_ascii_case(text))
                    .map(|&(v, _)| v);
                match (named, (!quoted).then(|| parse_uint(text)).flatten()) {
                    (_, Some(n)) | (Some(n), None) => Value::UInt(n),
                    (None, None) if names.is_empty() => {
                        return Err(err(format!("\"{text}\" isn't a whole number")));
                    }
                    (None, None) => {
                        return Err(err(format!(
                            "\"{text}\" isn't a number or a name for {name} values, like \"{}\"",
                            names[names.len().min(2) - 1].1
                        )));
                    }
                }
            }
            Kind::Time => {
                Value::Time(parse_seconds(text).ok_or_else(|| {
                    err(format!("\"{text}\" isn't a time; write seconds, like 0.5"))
                })?)
            }
            Kind::Str => {
                if !contains && let Field::Finding(FindingField::Category) = lhs.field {
                    let id = Category::ALL
                        .iter()
                        .map(|c| c.id())
                        .find(|id| id.eq_ignore_ascii_case(text))
                        .ok_or_else(|| {
                            err(format!(
                                "\"{text}\" isn't a category; they are dns, tcp, loss, slow, tls, http and capture"
                            ))
                        })?;
                    Value::Str(id.into())
                } else {
                    Value::Str(text.to_string().into())
                }
            }
            Kind::Ipv4 | Kind::Ipv6 => {
                let v6 = lhs.kind == Kind::Ipv6;
                return parse_address(text, v6).ok_or_else(|| {
                    err(format!(
                        "\"{text}\" isn't an {} address",
                        if v6 { "IPv6" } else { "IPv4" }
                    ))
                });
            }
            Kind::Ether => Value::Ether(parse_mac(text).ok_or_else(|| {
                err(format!(
                    "\"{text}\" isn't a MAC address like 02:00:00:00:00:01"
                ))
            })?),
            Kind::Bytes | Kind::Protocol if quoted => Value::Bytes(text.as_bytes().to_vec().into()),
            Kind::Bytes | Kind::Protocol => Value::Bytes(
                parse_bytes(text)
                    .ok_or_else(|| {
                        err(format!(
                            "{name} holds bytes: write them like 47:45:54, or as a quoted string"
                        ))
                    })?
                    .into(),
            ),
            Kind::Number => Value::Number(
                text.parse()
                    .ok()
                    .filter(|x: &f64| x.is_finite())
                    .ok_or_else(|| err(format!("\"{text}\" isn't a number")))?,
            ),
            Kind::Severity => Value::Severity(
                Severity::ALL
                    .into_iter()
                    .find(|s| s.name().eq_ignore_ascii_case(text))
                    .ok_or_else(|| {
                        err(format!(
                            "\"{text}\" isn't a severity: error, warning or info"
                        ))
                    })?,
            ),
            Kind::Marker => return Err(err(format!("{name} has no value"))),
        };
        Ok(Literal::Value(value))
    }
}

fn value_text(tok: &Token) -> Result<&str, FilterError> {
    match &tok.tok {
        Tok::Word(w) => Ok(w),
        Tok::Str(s) => Ok(s),
        Tok::Sym(_) => Err(FilterError::new(
            format!("expected a value, not {}", describe(tok)),
            tok.start,
            tok.end,
        )),
    }
}

fn describe(tok: &Token) -> String {
    match &tok.tok {
        Tok::Word(w) => format!("\"{w}\""),
        Tok::Str(s) => format!("\"{s}\""),
        Tok::Sym(s) => format!("\"{s}\""),
    }
}

fn unexpected(tok: &Token) -> FilterError {
    FilterError::new(
        format!("{} was unexpected here", describe(tok)),
        tok.start,
        tok.end,
    )
}

fn unknown_field(name: &str, tok: &Token) -> FilterError {
    let looks_like_value = name
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_digit() || c == ':');
    let message = if looks_like_value {
        format!("expected a field name, not \"{name}\"")
    } else {
        match closest(name) {
            Some(near) => format!("unknown field \"{name}\"; did you mean \"{near}\"?"),
            None => format!("unknown field \"{name}\"; \"packet-cage fields\" lists the fields"),
        }
    };
    FilterError::new(message, tok.start, tok.end)
}

/// The known field nearest to a misspelt one, if any is close.
fn closest(name: &str) -> Option<String> {
    let limit = (name.len() / 4).max(2);
    super::all_fields()
        .map(|(candidate, ..)| (edit_distance(name, &candidate), candidate))
        .filter(|(d, _)| *d <= limit)
        .min_by_key(|(d, _)| *d)
        .map(|(_, c)| c)
}

fn edit_distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut row: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut prev = row[0];
        row[0] = i + 1;
        for (j, &cb) in b.iter().enumerate() {
            let cur = row[j + 1];
            row[j + 1] = (prev + usize::from(ca != cb)).min(row[j] + 1).min(cur + 1);
            prev = cur;
        }
    }
    row[b.len()]
}

/// Decimal, 0x hex, 0b binary, or octal with a leading 0, as in Wireshark.
fn parse_uint(s: &str) -> Option<u64> {
    let (digits, radix) = if let Some(hex) = s.strip_prefix("0x").or(s.strip_prefix("0X")) {
        (hex, 16)
    } else if let Some(bin) = s.strip_prefix("0b").or(s.strip_prefix("0B")) {
        (bin, 2)
    } else if s.len() > 1 && s.starts_with('0') {
        (&s[1..], 8)
    } else {
        (s, 10)
    };
    if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
        return None;
    }
    u64::from_str_radix(digits, radix).ok()
}

/// "1.5" → 1,500,000,000 ns.
fn parse_seconds(s: &str) -> Option<i64> {
    let (negative, s) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s),
    };
    let (whole, frac) = s.split_once('.').unwrap_or((s, ""));
    let digits = |p: &str| p.bytes().all(|b| b.is_ascii_digit());
    if (whole.is_empty() && frac.is_empty()) || !digits(whole) || !digits(frac) {
        return None;
    }
    let secs: i64 = if whole.is_empty() {
        0
    } else {
        whole.parse().ok()?
    };
    let nanos = frac
        .bytes()
        .chain(std::iter::repeat(b'0'))
        .take(9)
        .fold(0i64, |n, d| n * 10 + i64::from(d - b'0'));
    let total = secs.checked_mul(1_000_000_000)?.checked_add(nanos)?;
    Some(if negative { -total } else { total })
}

/// An address, or a network written with a prefix length.
fn parse_address(s: &str, v6: bool) -> Option<Literal> {
    let (addr, prefix) = match s.split_once('/') {
        Some((addr, prefix)) => (addr, Some(prefix.parse::<u8>().ok()?)),
        None => (s, None),
    };
    let ip = if v6 {
        IpAddr::V6(addr.parse().ok()?)
    } else {
        IpAddr::V4(addr.parse().ok()?)
    };
    let full = if v6 { 128 } else { 32 };
    match prefix {
        Some(p) if p > full => None,
        Some(p) if p < full => Some(Literal::Net(ip, p)),
        _ => Some(Literal::Value(Value::Ip(ip))),
    }
}

/// `02:00:00:00:00:01`, `02-00-00-00-00-01` or `0200.0000.0001`.
fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let hex = |p: &str, len: usize| {
        (p.len() == len && p.chars().all(|c| c.is_ascii_hexdigit()))
            .then(|| u32::from_str_radix(p, 16).ok())
            .flatten()
    };
    let parts: Vec<&str> = s.split([':', '-']).collect();
    let bytes: Vec<u8> = if parts.len() == 6 {
        parts
            .iter()
            .map(|p| hex(p, 2).or_else(|| hex(p, 1)).map(|b| b as u8))
            .collect::<Option<_>>()?
    } else {
        let groups: Vec<&str> = s.split('.').collect();
        if groups.len() != 3 {
            return None;
        }
        groups
            .iter()
            .map(|g| hex(g, 4))
            .collect::<Option<Vec<u32>>>()?
            .into_iter()
            .flat_map(|g| [(g >> 8) as u8, g as u8])
            .collect()
    };
    bytes.try_into().ok()
}

/// `47:45:54`, `47-45-54` or `47.45.54`.
fn parse_bytes(s: &str) -> Option<Vec<u8>> {
    s.split([':', '-', '.'])
        .map(|p| {
            (p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
                .then(|| u8::from_str_radix(p, 16).ok())
                .flatten()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers() {
        assert_eq!(parse_uint("443"), Some(443));
        assert_eq!(parse_uint("0x12"), Some(18));
        assert_eq!(parse_uint("022"), Some(18));
        assert_eq!(parse_uint("0b10010"), Some(18));
        assert_eq!(parse_uint("0"), Some(0));
        assert_eq!(parse_uint("1.5"), None);
        assert_eq!(parse_uint("-1"), None);
        assert_eq!(parse_uint("09"), None);
        assert_eq!(parse_seconds("1.5"), Some(1_500_000_000));
        assert_eq!(parse_seconds("0.015"), Some(15_000_000));
        assert_eq!(parse_seconds(".5"), Some(500_000_000));
        assert_eq!(parse_seconds("-1"), Some(-1_000_000_000));
        assert_eq!(parse_seconds("500ms"), None);
    }

    #[test]
    fn addresses() {
        assert!(matches!(
            parse_address("10.0.0.0/8", false),
            Some(Literal::Net(_, 8))
        ));
        assert!(matches!(
            parse_address("10.0.0.1/32", false),
            Some(Literal::Value(Value::Ip(_)))
        ));
        assert!(parse_address("10.0.0.1/33", false).is_none());
        assert!(parse_address("fe80::1", false).is_none());
        assert!(parse_address("2001:db8::/32", true).is_some());
        let mac = [2, 0, 0, 0, 0, 1];
        assert_eq!(parse_mac("02:00:00:00:00:01"), Some(mac));
        assert_eq!(parse_mac("02-00-00-00-00-01"), Some(mac));
        assert_eq!(parse_mac("0200.0000.0001"), Some(mac));
        assert_eq!(parse_mac("02:00:00:00:00"), None);
        assert_eq!(parse_bytes("47:45:54"), Some(b"GET".to_vec()));
        assert_eq!(parse_bytes("GET"), None);
    }

    #[test]
    fn suggestions() {
        assert_eq!(closest("tcp.flags.rst").as_deref(), Some("tcp.flags.reset"));
        assert_eq!(closest("dns.qry_name").as_deref(), Some("dns.qry.name"));
        assert_eq!(
            closest("finding.severty").as_deref(),
            Some("finding.severity")
        );
        assert_eq!(closest("quic"), None);
    }

    fn parses(text: &str) {
        if let Err(e) = parse(text) {
            panic!("{text}: {}", e.in_filter(text));
        }
    }

    fn fails(text: &str, message: &str) {
        match parse(text) {
            Ok(_) => panic!("{text} parsed"),
            Err(e) => assert!(e.message.contains(message), "{text}: {}", e.message),
        }
    }

    #[test]
    fn grammar() {
        for text in [
            "tcp",
            "!tcp.analysis.flags",
            "tcp.port == 443 && !(ip.src == 10.0.0.0/8)",
            "tcp.port eq 443 or udp.port ne 53 and not icmp",
            "tcp.flags & 0x12 == 0x12",
            "tcp.flags & 0x02",
            "frame.number in {1, 3..5, 7 .. 9}",
            "frame.number not in {1}",
            "ip.addr in {10.0.0.1..10.0.0.9, 192.168.0.0/16}",
            "ip.src == ip.dst",
            "frame.len > frame.cap_len",
            "lower(dns.qry.name) == \"example.com\"",
            "len(dns.qry.name) > 30 && count(dns.a) >= 2",
            "dns.qry.type == AAAA && dns.flags.rcode == \"No such name\"",
            "dns.qry.name matches \"^api\\\\.\"",
            r#"dns.qry.name matches r"^api\.""#,
            "frame contains \"GET\" || tcp.payload contains 47:45:54",
            "dns.time > 0.5",
            "eth.addr == ff:ff:ff:ff:ff:ff",
            "ipv6.addr == 2001:db8::/32",
            "http.request.method in {\"GET\", HEAD}",
            "tcp.flags.syn == true ^^ tcp.flags.ack == 1",
            "finding.severity >= warning",
            "finding.category == DNS && finding.server_secs > 1",
            "finding.category == tls || finding.category in {dns, http}",
        ] {
            parses(text);
        }
    }

    #[test]
    fn mistakes() {
        fails("", "empty");
        fails("tcp.port ==", "ends where a value");
        fails("(tcp", "never closed");
        fails("tcp)", "unexpected");
        fails("tcp.port == 80 80", "unexpected");
        fails("frame.number in {1 3}", "commas");
        fails("frame.number in {}", "empty");
        fails("tcp.analysis.retransmission == 1", "no value to compare");
        fails("tcp.port contains 80", "contains and matches");
        fails("dns.qry.type == 1.5", "isn't a number");
        fails("dns.flags.rcode == NXDomain", "name for dns.flags.rcode");
        fails("dns.flags.response == yes", "true or false");
        fails("ip.src == fe80::1", "isn't an IPv4");
        fails("ip.src == dns.qry.name", "can't compare");
        fails("80 == tcp.port", "expected a field name");
        fails("\"x\" == tcp.port", "starts with a field name");
        fails("len(tcp.port) > 1", "string or bytes");
        fails("len(dns.qry.name)", "compare this");
        fails("dns.qry.name matches \"(\"", "regular expression");
        fails("finding.category == dsn", "isn't a category");
        fails("finding.severity == bad", "isn't a severity");
        fails("frame contains GET", "holds bytes");
    }
}
