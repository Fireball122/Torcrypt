// src/engine/crackers/generator.rs — Candidate Password & Mask Stream Generator
// Streams candidates from embedded dictionaries, external wordlists, or brute-force masks.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use super::rules::{best64_rules, Rule};

pub static EMBEDDED_WORDLIST_RAW: &str = include_str!("embedded_wordlist.txt");
pub const EMBEDDED_WORDLIST_COUNT: u64 = 27_601;
pub const COMMON_PASSWORDS: &[&str] = &[
    // ── Top numeric & keyboard patterns ──────────────────────────────────────
    "123456","password","12345678","qwerty","123456789","12345","1234","111111",
    "1234567","dragon","123123","baseball","football","welcome","monkey","shadow",
    "mustang","michael","superman","jordan","access","harley","rangers","bullet",
    "robert","silver","charlie","thomas","orange","mercedes","cheese","killer",
    "secret","cookie","princess","albert","summer","trustno1","hunter","george",
    "jumper","barney","marvin","buster","freedom","galaxy","spiderman","champion",
    "thunder","captain","william","corvette","morgan","computer","miller","andrew",
    "matrix","falcon","daniel","pepper","guitar","walter","hammer","spring",
    "doctor","sunset","samuel","yellow","coffee","bandit","boston","dakota",
    "golden","simpson","panther","donald","anthony","ferrari","phoenix","trouble",
    "magic","chelsea","winner","diamond","player","chester","diesel","cougar",
    "jackson","cowboy","corrado","martin","hannah","jaguar","bailey","cooper",
    "timber","brandy","stella","porter","edward","casper","oliver","hunter2",
    // ── Common service / default credentials ─────────────────────────────────
    "admin","root","toor","pass","login","guest","default","changeme","letmein",
    "pass123","password1","password123","secret123","admin123","welcome1","admin1",
    "test","test123","user","user123","abc123","iloveyou","sunshine","master",
    "hello","hello123","login123","qwerty123","qwerty1","pass@word","pass1",
    "passw0rd","p@ssword","p@ssw0rd","P@ssw0rd","P@ssword1","P@ssword123",
    "Password1","Password@1","Password@123","Password1!","123qwe","123abc",
    "1q2w3e","1qaz2wsx","qazwsx","qweasd","!@#$%^&*","password!","password#1",
    // ── Seasonal / year patterns (rockyou top patterns) ──────────────────────
    "Summer2024!","Summer2025!","Summer2026!","Winter2024!","Winter2025!","Winter2026!",
    "Spring2024!","Spring2025!","Fall2024!","Autumn2024!",
    "Password2024","Password2025","Password2026","Admin2024","Admin2025",
    "Welcome2024","Welcome2025","Letmein2024","Letmein2025",
    "password2024","password2025","password2026","admin2024","admin2025",
    "welcome2024","welcome2025","letmein2024","letmein2025",
    // ── 4-8 digit pins and codes ─────────────────────────────────────────────
    "0000","1111","2222","3333","4444","5555","6666","7777","8888","9999",
    "1234","4321","1212","2121","6969","1337","1998","1999","2000","2001",
    "2002","2003","2004","2005","2006","2007","2008","2009","2010","2011",
    "2012","2013","2014","2015","2016","2017","2018","2019","2020","2021",
    "2022","2023","2024","2025","2026",
    "12345","54321","11111","22222","55555","00000","99999",
    "123456","654321","111111","999999","000000","696969",
    "1234567","12345678","123456789","1234567890",
    // ── Names & words (rockyou representative sample) ─────────────────────────
    "ashley","jessica","michael","andrew","joshua","daniel","matthew","nicholas",
    "angela","michelle","amanda","jennifer","melissa","stephanie","heather","nicole",
    "amanda1","jessica1","michael1","jordan23","jordan1","lebron","kobe","tiger",
    "soccer","hockey","baseball","basketball","football1","nascar","tennis",
    "mustang1","camaro","corvette1","honda","toyota","nissan","dodge","bmw","audi",
    "batman","superman1","spiderman1","ironman","wolverine","captain1","avengers",
    "starwars","stargate","startrek","matrix1","terminator","transformer",
    "thematrix","indiana","harrypotter","hermione","dumbledore","voldemort",
    "liverpool","chelsea1","arsenal","manchester","barcelona","madrid","juventus",
    "rangers1","yankees","redsox","cowboys","patriots","steelers","eagles",
    "iloveyou1","iloveyou2","ilove","loveyou","loveme","babygirl","babyboy",
    "monkey1","dragon1","shadow1","tiger1","panther1","eagle1","falcon1","cobra",
    "hunter1","master1","ranger1","maverick","predator","commando","soldier",
    // ── Common Wi-Fi / router defaults ───────────────────────────────────────
    "wifi","wireless","internet","network","router","modem","linksys","netgear",
    "belkin","dlink","asus","cisco","ubiquiti","openwrt","ddwrt","tomato",
    "admin123!","Admin1234","router123","wifi1234","password01","Password01",
    // ── Common KeePass / vault passwords found in breaches ───────────────────
    "masterkey","master123","vault123","keepass","keepassword","MyVault",
    "safepassword","SafePass","1Password","onepassword","passmanager",
    // ── Leet-speak common variants (for targets that don't use rules) ─────────
    "p4ssw0rd","pa$$word","p@55w0rd","l3tm3in","s3cr3t","4dm1n","r00t",
    "h4x0r","1337speak","su93r","p@$$w0rd","@dm1n","pa55w0rd","Pa55w0rd",
    // ── Keyboard walks ────────────────────────────────────────────────────────
    "qwertyuiop","asdfghjkl","zxcvbnm","qwerty123","asdf1234","zxcvbn",
    "qazxsw","qazxswedcvfr","1qazxsw2","2wsxcde3","qwerasdf","asdfqwer",
    // ── Short common words ────────────────────────────────────────────────────
    "love","hate","home","work","play","life","time","good","best","cool",
    "god","sex","hot","new","old","big","bad","man","war","win","top","pro",
    "god123","sex123","love123","home123","work123","life123","time123",
];

#[derive(Debug, Clone)]
pub enum MaskToken {
    Charset(Vec<char>),
    Literal(char),
}

impl MaskToken {
    pub fn len(&self) -> usize {
        match self {
            MaskToken::Charset(c) => c.len(),
            MaskToken::Literal(_) => 1,
        }
    }

    pub fn char_at(&self, idx: usize) -> char {
        match self {
            MaskToken::Charset(c) => c[idx],
            MaskToken::Literal(ch) => *ch,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CompiledMask {
    pub tokens:   Vec<MaskToken>,
    pub counters: Vec<usize>,
    pub total:    u64,
    pub current:  u64,
}

impl CompiledMask {
    pub fn parse(pattern: &str) -> Self {
        let mut tokens = Vec::new();
        let mut chars = pattern.chars().peekable();

        let digits: Vec<char> = "0123456789".chars().collect();
        let lower: Vec<char> = "abcdefghijklmnopqrstuvwxyz".chars().collect();
        let upper: Vec<char> = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".chars().collect();
        let symbols: Vec<char> = "!@#$%^&*()-_=+[]{}|;:,.<>?/`~\"'\\".chars().collect();
        let mut all: Vec<char> = Vec::new();
        all.extend_from_slice(&lower);
        all.extend_from_slice(&upper);
        all.extend_from_slice(&digits);
        all.extend_from_slice(&symbols);

        while let Some(c) = chars.next() {
            if c == '?' {
                match chars.next() {
                    Some('d') => tokens.push(MaskToken::Charset(digits.clone())),
                    Some('l') => tokens.push(MaskToken::Charset(lower.clone())),
                    Some('u') => tokens.push(MaskToken::Charset(upper.clone())),
                    Some('s') => tokens.push(MaskToken::Charset(symbols.clone())),
                    Some('a') => tokens.push(MaskToken::Charset(all.clone())),
                    Some('?') => tokens.push(MaskToken::Literal('?')),
                    Some(other) => {
                        tokens.push(MaskToken::Literal('?'));
                        tokens.push(MaskToken::Literal(other));
                    }
                    None => tokens.push(MaskToken::Literal('?')),
                }
            } else {
                tokens.push(MaskToken::Literal(c));
            }
        }

        let total: u64 = tokens.iter().map(|t| t.len() as u64).product();
        let counters = vec![0usize; tokens.len()];

        Self {
            tokens,
            counters,
            total: total.max(1),
            current: 0,
        }
    }
}

pub enum CandidateSource {
    EmbeddedWordlist { offset: usize },
    EmbeddedCommon { word_idx: usize, pin_cur: u64, pin_max: u64 },
    NumericMask { current: u64, max: u64, digits: usize },
    Mask(CompiledMask),
    RuleMutated { words: Vec<String>, rules: Vec<Rule>, word_idx: usize, rule_idx: usize, total: u64 },
    Combinator { left: Vec<String>, right: Vec<String>, left_idx: usize, right_idx: usize, total: u64 },
    WordlistFile(BufReader<File>),
    CustomList(Vec<String>),
}
pub struct CandidateIterator {
    source: CandidateSource,
    done: bool,
}

impl CandidateIterator {
    /// Construct a common-candidate iterator using the built-in 27,601-entry breach corpus.
    /// High-frequency breach passwords (password, 123456, admin, secret123) are prioritized first.
    pub fn new_common() -> Self {
        Self {
            source: CandidateSource::EmbeddedWordlist { offset: 0 },
            done: false,
        }
    }

    /// Returns true if a system wordlist (rockyou etc.) was found at any standard path.
    pub fn system_wordlist_path() -> Option<&'static str> {
        const ROCKYOU_PATHS: &[&str] = &[
            "/home/ultaria/wordlists/rockyou.txt",
            "/home/ultaria/wordlists/xato-top100k.txt",
            "/home/ultaria/wordlists/100k-most-used-ncsc.txt",
            "/usr/share/wordlists/rockyou.txt",
            "/usr/share/john/password.lst",
            "/usr/share/hashcat/wordlists/rockyou.txt",
            "/opt/wordlists/rockyou.txt",
            "rockyou.txt",
            "wordlist.txt",
        ];
        ROCKYOU_PATHS.iter().find(|&&p| std::path::Path::new(p).is_file()).copied()
    }

    pub fn total_candidates(&self) -> Option<u64> {
        match &self.source {
            CandidateSource::EmbeddedWordlist { .. } => Some(EMBEDDED_WORDLIST_COUNT),
            CandidateSource::EmbeddedCommon { pin_max, .. } => {
                Some(COMMON_PASSWORDS.len() as u64 + pin_max)
            }
            CandidateSource::NumericMask { max, .. } => Some(*max),
            CandidateSource::Mask(m) => Some(m.total),
            CandidateSource::RuleMutated { total, .. } => Some(*total),
            CandidateSource::Combinator { total, .. } => Some(*total),
            CandidateSource::CustomList(list) => Some(list.len() as u64),
            CandidateSource::WordlistFile(_) => None,
        }
    }
    pub fn new_numeric_mask(digits: usize) -> Self {
        let max = 10u64.pow(digits as u32);
        Self {
            source: CandidateSource::NumericMask {
                current: 0,
                max,
                digits,
            },
            done: false,
        }
    }

    pub fn new_mask(pattern: &str) -> Self {
        Self {
            source: CandidateSource::Mask(CompiledMask::parse(pattern)),
            done: false,
        }
    }

    pub fn new_wordlist(path: PathBuf) -> Option<Self> {
        let file = File::open(path).ok()?;
        Some(Self {
            source: CandidateSource::WordlistFile(BufReader::new(file)),
            done: false,
        })
    }

    pub fn new_custom(list: Vec<String>) -> Self {
        Self {
            source: CandidateSource::CustomList(list),
            done: false,
        }
    }

    pub fn new_best64(words: Vec<String>) -> Self {
        let rules = best64_rules();
        let total = (words.len() * rules.len()) as u64;
        Self {
            source: CandidateSource::RuleMutated {
                words,
                rules,
                word_idx: 0,
                rule_idx: 0,
                total,
            },
            done: false,
        }
    }

    pub fn new_combinator(left: Vec<String>, right: Vec<String>) -> Self {
        let total = (left.len() * right.len()) as u64;
        Self {
            source: CandidateSource::Combinator {
                left,
                right,
                left_idx: 0,
                right_idx: 0,
                total,
            },
            done: false,
        }
    }

    pub fn skip_candidates(&mut self, mut count: u64) {
        while count > 0 && !self.done {
            let take = count.min(1000) as usize;
            let batch = self.next_batch(take);
            if batch.is_empty() {
                break;
            }
            count -= batch.len() as u64;
        }
    }

    pub fn next_batch(&mut self, batch_size: usize) -> Vec<String> {
        if self.done {
            return Vec::new();
        }

        let mut batch = Vec::with_capacity(batch_size);

        match &mut self.source {
            CandidateSource::EmbeddedWordlist { offset } => {
                if *offset >= EMBEDDED_WORDLIST_RAW.len() {
                    self.done = true;
                } else {
                    let remainder = &EMBEDDED_WORDLIST_RAW[*offset..];
                    for line in remainder.lines() {
                        if batch.len() >= batch_size {
                            break;
                        }
                        let trimmed = line.trim();
                        if !trimmed.is_empty() {
                            batch.push(trimmed.to_string());
                        }
                        *offset += line.len() + 1; // line bytes + newline
                    }
                    if *offset >= EMBEDDED_WORDLIST_RAW.len() || batch.is_empty() {
                        self.done = true;
                    }
                }
            }
            CandidateSource::EmbeddedCommon { word_idx, pin_cur, pin_max } => {
                while *word_idx < COMMON_PASSWORDS.len() && batch.len() < batch_size {
                    batch.push(COMMON_PASSWORDS[*word_idx].to_string());
                    *word_idx += 1;
                }
                while *pin_cur < *pin_max && batch.len() < batch_size {
                    batch.push(format!("{:04}", *pin_cur));
                    *pin_cur += 1;
                }
                if *word_idx >= COMMON_PASSWORDS.len() && *pin_cur >= *pin_max {
                    self.done = true;
                }
            }
            CandidateSource::NumericMask { current, max, digits } => {
                while *current < *max && batch.len() < batch_size {
                    batch.push(format!("{:0width$}", *current, width = *digits));
                    *current += 1;
                }
                if *current >= *max {
                    self.done = true;
                }
            }
            CandidateSource::WordlistFile(reader) => {
                let mut line = String::new();
                while batch.len() < batch_size {
                    line.clear();
                    match reader.read_line(&mut line) {
                        Ok(0) => {
                            self.done = true;
                            break;
                        }
                        Ok(_) => {
                            let trimmed = line.trim();
                            if !trimmed.is_empty() {
                                batch.push(trimmed.to_string());
                            }
                        }
                        Err(_) => {
                            self.done = true;
                            break;
                        }
                    }
                }
            }
            CandidateSource::CustomList(list) => {
                let take_count = batch_size.min(list.len());
                let drained: Vec<String> = list.drain(0..take_count).collect();
                batch.extend(drained);
                if list.is_empty() {
                    self.done = true;
                }
            }
            CandidateSource::Mask(mask) => {
                let n = mask.tokens.len();
                if n == 0 {
                    self.done = true;
                } else {
                    while mask.current < mask.total && batch.len() < batch_size {
                        let cand: String = mask.tokens.iter().zip(&mask.counters).map(|(t, &idx)| t.char_at(idx)).collect();
                        batch.push(cand);
                        mask.current += 1;

                        let mut carry = true;
                        for i in (0..n).rev() {
                            if carry {
                                mask.counters[i] += 1;
                                if mask.counters[i] >= mask.tokens[i].len() {
                                    mask.counters[i] = 0;
                                    carry = true;
                                } else {
                                    carry = false;
                                }
                            }
                        }
                        if carry {
                            self.done = true;
                            break;
                        }
                    }
                    if mask.current >= mask.total {
                        self.done = true;
                    }
                }
            }
            CandidateSource::RuleMutated { words, rules, word_idx, rule_idx, .. } => {
                while *word_idx < words.len() && batch.len() < batch_size {
                    let w = &words[*word_idx];
                    let r = &rules[*rule_idx];
                    batch.push(r.apply(w));

                    *rule_idx += 1;
                    if *rule_idx >= rules.len() {
                        *rule_idx = 0;
                        *word_idx += 1;
                    }
                }
                if *word_idx >= words.len() {
                    self.done = true;
                }
            }
            CandidateSource::Combinator { left, right, left_idx, right_idx, .. } => {
                while *left_idx < left.len() && batch.len() < batch_size {
                    let l = &left[*left_idx];
                    let r = &right[*right_idx];
                    batch.push(format!("{}{}", l, r));

                    *right_idx += 1;
                    if *right_idx >= right.len() {
                        *right_idx = 0;
                        *left_idx += 1;
                    }
                }
                if *left_idx >= left.len() {
                    self.done = true;
                }
            }
        }

        batch
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_common_candidates() {
        let mut iter = CandidateIterator::new_common();
        let batch = iter.next_batch(500);
        assert!(!batch.is_empty());
        assert!(batch.iter().any(|s| s == "password"));
        assert!(batch.iter().any(|s| s == "secret123"));
    }

    #[test]
    fn test_numeric_mask() {
        let mut iter = CandidateIterator::new_numeric_mask(4);
        let batch = iter.next_batch(10);
        assert_eq!(batch.len(), 10);
        assert_eq!(batch[0], "0000");
        assert_eq!(batch[9], "0009");
    }

    #[test]
    fn test_common_multi_batch_exhaustion() {
        let mut iter = CandidateIterator::new_common();
        let total = iter.total_candidates().unwrap();
        let mut count = 0;
        loop {
            let batch = iter.next_batch(500);
            if batch.is_empty() {
                break;
            }
            count += batch.len() as u64;
        }
        assert_eq!(count, total);
        assert!(count > 10_000);
    }

    #[test]
    fn test_charset_mask_compiler() {
        let mut iter = CandidateIterator::new_mask("Pass?d?d");
        assert_eq!(iter.total_candidates(), Some(100));

        let batch = iter.next_batch(50);
        assert_eq!(batch.len(), 50);
        assert_eq!(batch[0], "Pass00");
        assert_eq!(batch[1], "Pass01");

        let batch2 = iter.next_batch(60);
        assert_eq!(batch2.len(), 50);
        assert_eq!(batch2[49], "Pass99");

        let empty = iter.next_batch(10);
        assert!(empty.is_empty());
    }

    #[test]
    fn test_best64_iterator() {
        let words = vec!["password".to_string(), "admin".to_string()];
        let mut iter = CandidateIterator::new_best64(words);
        assert_eq!(iter.total_candidates(), Some(128));

        let batch = iter.next_batch(200);
        assert_eq!(batch.len(), 128);
        assert!(batch.contains(&"Password".to_string()));
        assert!(batch.contains(&"Password123".to_string()));
        assert!(batch.contains(&"Admin!".to_string()));
    }

    #[test]
    fn test_combinator_iterator() {
        let left = vec!["blue".to_string(), "fire".to_string()];
        let right = vec!["sky".to_string(), "truck".to_string(), "bird".to_string()];
        let mut iter = CandidateIterator::new_combinator(left, right);
        assert_eq!(iter.total_candidates(), Some(6));

        let batch = iter.next_batch(10);
        assert_eq!(batch.len(), 6);
        assert_eq!(batch[0], "bluesky");
        assert_eq!(batch[1], "bluetruck");
        assert_eq!(batch[2], "bluebird");
        assert_eq!(batch[3], "firesky");
        assert_eq!(batch[4], "firetruck");
        assert_eq!(batch[5], "firebird");
    }
}
