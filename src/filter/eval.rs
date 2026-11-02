//! The parsed form of a filter, and how it is tested.

use std::borrow::Cow;
use std::cmp::Ordering;
use std::net::IpAddr;

use regex_lite::Regex;

use super::Field;
use crate::diagnose::Severity;

/// One occurrence of a field.
#[derive(Debug, Clone, PartialEq)]
pub enum Value<'a> {
    /// A field that is only there or not.
    Present,
    Bool(bool),
    UInt(u64),
    /// Nanoseconds. Relative times can be negative.
    Time(i64),
    Str(Cow<'a, str>),
    Ip(IpAddr),
    Ether([u8; 6]),
    Bytes(Cow<'a, [u8]>),
    Number(f64),
    Severity(Severity),
}

/// A packet or finding a filter can test.
pub trait Source {
    /// Every occurrence of `field`; empty when it isn't there.
    fn values(&self, field: Field) -> Vec<Value<'_>>;
}

#[derive(Debug, Clone)]
pub enum Expr {
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Xor(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Exists(Field),
    /// `tcp.flags & 0x02`: some occurrence has one of the bits set.
    Nonzero(Operand),
    Compare(Operand, Cmp, Rhs),
    In {
        lhs: Operand,
        set: Vec<SetItem>,
        /// `not in`: no occurrence is in the set.
        negated: bool,
    },
}

/// The left side of a comparison: a field, or a function of one.
#[derive(Debug, Clone, Copy)]
pub enum Operand {
    Field(Field),
    Lower(Field),
    Upper(Field),
    Len(Field),
    Count(Field),
    /// `field & mask`
    Mask(Field, u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cmp {
    /// `==`: some occurrence is equal.
    AnyEq,
    /// `!=`: every occurrence differs.
    AllNe,
    /// `===`: every occurrence is equal.
    AllEq,
    /// `!==`: some occurrence differs.
    AnyNe,
    Gt,
    Ge,
    Lt,
    Le,
    Contains,
    Matches,
}

#[derive(Debug, Clone)]
pub enum Rhs {
    Literal(Literal),
    Regex(Regex),
    Operand(Operand),
}

#[derive(Debug, Clone)]
pub enum Literal {
    Value(Value<'static>),
    /// An address with a shorter prefix: every address in the network.
    Net(IpAddr, u8),
}

#[derive(Debug, Clone)]
pub enum SetItem {
    One(Literal),
    Range(Literal, Literal),
}

pub fn test(expr: &Expr, src: &dyn Source) -> bool {
    match expr {
        Expr::And(a, b) => test(a, src) && test(b, src),
        Expr::Or(a, b) => test(a, src) || test(b, src),
        Expr::Xor(a, b) => test(a, src) != test(b, src),
        Expr::Not(a) => !test(a, src),
        Expr::Exists(field) => !src.values(*field).is_empty(),
        Expr::Nonzero(op) => operand(op, src)
            .iter()
            .any(|v| matches!(v, Value::UInt(n) if *n != 0)),
        Expr::Compare(lhs, cmp, rhs) => compare(lhs, *cmp, rhs, src),
        Expr::In { lhs, set, negated } => {
            let values = operand(lhs, src);
            if *negated {
                !values.is_empty() && values.iter().all(|v| !in_set(v, set))
            } else {
                values.iter().any(|v| in_set(v, set))
            }
        }
    }
}

fn operand<'a>(op: &Operand, src: &'a dyn Source) -> Vec<Value<'a>> {
    let map = |field: Field, f: &dyn Fn(Value<'a>) -> Option<Value<'a>>| {
        src.values(field).into_iter().filter_map(f).collect()
    };
    match *op {
        Operand::Field(field) => src.values(field),
        Operand::Lower(field) => map(field, &|v| match v {
            Value::Str(s) => Some(Value::Str(Cow::Owned(s.to_lowercase()))),
            _ => None,
        }),
        Operand::Upper(field) => map(field, &|v| match v {
            Value::Str(s) => Some(Value::Str(Cow::Owned(s.to_uppercase()))),
            _ => None,
        }),
        Operand::Len(field) => map(field, &|v| match v {
            Value::Str(s) => Some(Value::UInt(s.len() as u64)),
            Value::Bytes(b) => Some(Value::UInt(b.len() as u64)),
            _ => None,
        }),
        Operand::Count(field) => vec![Value::UInt(src.values(field).len() as u64)],
        Operand::Mask(field, mask) => map(field, &|v| match v {
            Value::UInt(n) => Some(Value::UInt(n & mask)),
            _ => None,
        }),
    }
}

fn compare(lhs: &Operand, cmp: Cmp, rhs: &Rhs, src: &dyn Source) -> bool {
    let left = operand(lhs, src);
    match rhs {
        Rhs::Regex(re) => left.iter().any(|v| regex_match(v, re)),
        Rhs::Literal(lit) => quantify(cmp, left.iter(), |v| holds_literal(v, cmp, lit)),
        Rhs::Operand(op) => {
            let right = operand(op, src);
            if right.is_empty() {
                return false;
            }
            let pairs = left.iter().flat_map(|a| right.iter().map(move |b| (a, b)));
            quantify(cmp, pairs, |(a, b)| holds(a, cmp, b))
        }
    }
}

/// Applies `holds` (the relation without its negation) to every item, the
/// way the operator asks: some, every, some not or none.
fn quantify<T>(cmp: Cmp, items: impl Iterator<Item = T>, holds: impl Fn(T) -> bool) -> bool {
    let mut items = items.peekable();
    if items.peek().is_none() {
        return false;
    }
    match cmp {
        Cmp::AllNe => items.all(|x| !holds(x)),
        Cmp::AllEq => items.all(holds),
        Cmp::AnyNe => items.any(|x| !holds(x)),
        _ => items.any(holds),
    }
}

fn holds(a: &Value<'_>, cmp: Cmp, b: &Value<'_>) -> bool {
    let order = || order(a, b);
    match cmp {
        Cmp::AnyEq | Cmp::AllNe | Cmp::AllEq | Cmp::AnyNe => order() == Some(Ordering::Equal),
        Cmp::Gt => order() == Some(Ordering::Greater),
        Cmp::Ge => matches!(order(), Some(Ordering::Greater | Ordering::Equal)),
        Cmp::Lt => order() == Some(Ordering::Less),
        Cmp::Le => matches!(order(), Some(Ordering::Less | Ordering::Equal)),
        Cmp::Contains => contains(a, b),
        Cmp::Matches => false,
    }
}

fn holds_literal(v: &Value<'_>, cmp: Cmp, lit: &Literal) -> bool {
    match lit {
        Literal::Value(x) => holds(v, cmp, x),
        Literal::Net(net, prefix) => match cmp {
            Cmp::AnyEq | Cmp::AllNe | Cmp::AllEq | Cmp::AnyNe => {
                matches!(v, Value::Ip(ip) if in_network(*ip, *net, *prefix))
            }
            _ => holds(v, cmp, &Value::Ip(*net)),
        },
    }
}

fn in_set(v: &Value<'_>, set: &[SetItem]) -> bool {
    set.iter().any(|item| match item {
        SetItem::One(lit) => holds_literal(v, Cmp::AnyEq, lit),
        SetItem::Range(lo, hi) => holds_literal(v, Cmp::Ge, lo) && holds_literal(v, Cmp::Le, hi),
    })
}

fn order(a: &Value<'_>, b: &Value<'_>) -> Option<Ordering> {
    Some(match (a, b) {
        (Value::Bool(x), Value::Bool(y)) => x.cmp(y),
        (Value::UInt(x), Value::UInt(y)) => x.cmp(y),
        (Value::Time(x), Value::Time(y)) => x.cmp(y),
        (Value::Str(x), Value::Str(y)) => x.as_bytes().cmp(y.as_bytes()),
        (Value::Ip(x @ IpAddr::V4(_)), Value::Ip(y @ IpAddr::V4(_)))
        | (Value::Ip(x @ IpAddr::V6(_)), Value::Ip(y @ IpAddr::V6(_))) => x.cmp(y),
        (Value::Ether(x), Value::Ether(y)) => x.cmp(y),
        (Value::Bytes(x), Value::Bytes(y)) => x.cmp(y),
        (Value::Number(x), Value::Number(y)) => x.partial_cmp(y)?,
        (Value::Severity(x), Value::Severity(y)) => x.cmp(y),
        _ => return None,
    })
}

fn contains(a: &Value<'_>, b: &Value<'_>) -> bool {
    match (a, b) {
        (Value::Str(hay), Value::Str(needle)) => hay.contains(needle.as_ref()),
        (Value::Bytes(hay), Value::Bytes(needle)) => {
            needle.is_empty() || hay.windows(needle.len()).any(|w| w == needle.as_ref())
        }
        _ => false,
    }
}

fn regex_match(v: &Value<'_>, re: &Regex) -> bool {
    match v {
        Value::Str(s) => re.is_match(s),
        // Bytes are matched one character per byte, so `\x00` and the like
        // can be searched for.
        Value::Bytes(b) => re.is_match(&b.iter().map(|&b| char::from(b)).collect::<String>()),
        _ => false,
    }
}

fn in_network(ip: IpAddr, net: IpAddr, prefix: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(ip), IpAddr::V4(net)) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
            u32::from(ip) & mask == u32::from(net) & mask
        }
        (IpAddr::V6(ip), IpAddr::V6(net)) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
            u128::from(ip) & mask == u128::from(net) & mask
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn networks() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert!(in_network(ip("10.1.2.3"), ip("10.0.0.0"), 8));
        assert!(!in_network(ip("11.1.2.3"), ip("10.0.0.0"), 8));
        assert!(in_network(ip("11.1.2.3"), ip("10.0.0.0"), 0));
        assert!(in_network(ip("2001:db8::1"), ip("2001:db8::"), 32));
        assert!(!in_network(ip("2001:db9::1"), ip("2001:db8::"), 32));
        assert!(!in_network(ip("10.0.0.1"), ip("::"), 0));
    }

    #[test]
    fn byte_search() {
        let bytes = |b: &'static [u8]| Value::Bytes(Cow::Borrowed(b));
        assert!(contains(&bytes(b"xxGETxx"), &bytes(b"GET")));
        assert!(!contains(&bytes(b"GE"), &bytes(b"GET")));
        let re = regex_lite::RegexBuilder::new("^get")
            .case_insensitive(true)
            .build()
            .unwrap();
        assert!(regex_match(&bytes(b"GET / HTTP/1.1\xff"), &re));
    }
}
