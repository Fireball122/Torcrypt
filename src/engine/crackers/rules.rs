// src/engine/crackers/rules.rs — Password Rule Permutation & Mutation Engine
// Implements standard Hashcat/JtR rules (c, u, l, t, r, d, $, ^, s) and the standard Best64 rule set.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleOp {
    Noop,                     // :
    Lowercase,                // l
    Uppercase,                // u
    Capitalize,               // c (first letter uppercase, rest lowercase)
    InvertCapitalize,         // C (first letter lowercase, rest uppercase)
    ToggleCase,               // t (invert case of all characters)
    Reverse,                  // r
    Duplicate,                // d (pass -> passpass)
    Append(char),             // $x
    Prepend(char),            // ^x
    Substitute(char, char),   // sx y
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub ops: Vec<RuleOp>,
}

impl Rule {
    pub fn new(ops: Vec<RuleOp>) -> Self {
        Self { ops }
    }

    pub fn noop() -> Self {
        Self { ops: vec![RuleOp::Noop] }
    }

    pub fn parse(line: &str) -> Self {
        let mut ops = Vec::new();
        let chars: Vec<char> = line.chars().collect();
        let mut i = 0;

        while i < chars.len() {
            match chars[i] {
                ' ' | '\t' | ':' => { i += 1; }
                'l' => { ops.push(RuleOp::Lowercase); i += 1; }
                'u' => { ops.push(RuleOp::Uppercase); i += 1; }
                'c' => { ops.push(RuleOp::Capitalize); i += 1; }
                'C' => { ops.push(RuleOp::InvertCapitalize); i += 1; }
                't' => { ops.push(RuleOp::ToggleCase); i += 1; }
                'r' => { ops.push(RuleOp::Reverse); i += 1; }
                'd' => { ops.push(RuleOp::Duplicate); i += 1; }
                '$' => {
                    if i + 1 < chars.len() {
                        ops.push(RuleOp::Append(chars[i + 1]));
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                '^' => {
                    if i + 1 < chars.len() {
                        ops.push(RuleOp::Prepend(chars[i + 1]));
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                's' => {
                    if i + 2 < chars.len() {
                        ops.push(RuleOp::Substitute(chars[i + 1], chars[i + 2]));
                        i += 3;
                    } else {
                        i += 1;
                    }
                }
                _ => { i += 1; }
            }
        }

        if ops.is_empty() {
            ops.push(RuleOp::Noop);
        }

        Self { ops }
    }

    pub fn apply(&self, input: &str) -> String {
        let mut result = input.to_string();

        for op in &self.ops {
            match op {
                RuleOp::Noop => {}
                RuleOp::Lowercase => {
                    result = result.to_lowercase();
                }
                RuleOp::Uppercase => {
                    result = result.to_uppercase();
                }
                RuleOp::Capitalize => {
                    let mut chars = result.chars();
                    result = match chars.next() {
                        None => String::new(),
                        Some(first) => {
                            let mut s = first.to_uppercase().to_string();
                            s.push_str(&chars.as_str().to_lowercase());
                            s
                        }
                    };
                }
                RuleOp::InvertCapitalize => {
                    let mut chars = result.chars();
                    result = match chars.next() {
                        None => String::new(),
                        Some(first) => {
                            let mut s = first.to_lowercase().to_string();
                            s.push_str(&chars.as_str().to_uppercase());
                            s
                        }
                    };
                }
                RuleOp::ToggleCase => {
                    result = result.chars().map(|c| {
                        if c.is_lowercase() {
                            c.to_uppercase().collect::<String>()
                        } else {
                            c.to_lowercase().collect::<String>()
                        }
                    }).collect();
                }
                RuleOp::Reverse => {
                    result = result.chars().rev().collect();
                }
                RuleOp::Duplicate => {
                    let clone = result.clone();
                    result.push_str(&clone);
                }
                RuleOp::Append(ch) => {
                    result.push(*ch);
                }
                RuleOp::Prepend(ch) => {
                    let mut s = ch.to_string();
                    s.push_str(&result);
                    result = s;
                }
                RuleOp::Substitute(from, to) => {
                    result = result.replace(*from, &to.to_string());
                }
            }
        }

        result
    }
}

/// The standard Hashcat Best64 rule set
pub fn best64_rules() -> Vec<Rule> {
    const RAW_RULES: &[&str] = &[
        ":",
        "c",
        "l",
        "u",
        "C",
        "t",
        "r",
        "d",
        "$1",
        "$2",
        "$3",
        "$0",
        "$!",
        "$?",
        "$.",
        "$_",
        "$@",
        "$#",
        "$$",
        "^1",
        "^!",
        "c $1",
        "c $!",
        "c $?",
        "c $1 $2 $3",
        "c $2 $0 $2 $4",
        "c $2 $0 $2 $5",
        "c $2 $0 $2 $6",
        "so0",
        "se3",
        "si1",
        "sa@",
        "ss$",
        "c so0",
        "c se3",
        "c si1",
        "c sa@",
        "c ss$",
        "c so0 $1",
        "c se3 $1",
        "c sa@ $!",
        "c ss$ $!",
        "c $0 $1",
        "c $0 $2",
        "c $1 $2",
        "c $2 $3",
        "c $6 $9",
        "c $7 $7",
        "c $8 $8",
        "c $9 $9",
        "$1 $2",
        "$1 $2 $3",
        "$1 $2 $3 $4",
        "$1 $2 $3 $4 $5",
        "$1 $2 $3 $4 $5 $6",
        "$2 $0 $2 $4",
        "$2 $0 $2 $5",
        "$2 $0 $2 $6",
        "d $1",
        "r $1",
        "^$ $!",
        "^@ $#",
        "c $!",
        "c $#",
    ];

    RAW_RULES.iter().map(|s| Rule::parse(s)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_mutations() {
        let r_cap = Rule::parse("c");
        assert_eq!(r_cap.apply("password"), "Password");

        let r_app = Rule::parse("$1 $2 $3");
        assert_eq!(r_app.apply("pass"), "pass123");

        let r_sub = Rule::parse("sa@ se3");
        assert_eq!(r_sub.apply("password"), "p@ssword");

        let r_prep = Rule::parse("^! $!");
        assert_eq!(r_prep.apply("admin"), "!admin!");

        let r_rev = Rule::parse("r");
        assert_eq!(r_rev.apply("12345"), "54321");

        let r_dup = Rule::parse("d");
        assert_eq!(r_dup.apply("pass"), "passpass");
    }

    #[test]
    fn test_best64_count() {
        let rules = best64_rules();
        assert_eq!(rules.len(), 64);
        let mut mutated = Vec::new();
        for r in &rules {
            mutated.push(r.apply("password"));
        }
        assert!(mutated.contains(&"Password".to_string()));
        assert!(mutated.contains(&"Password123".to_string()));
        assert!(mutated.contains(&"Password!".to_string()));
    }
}
