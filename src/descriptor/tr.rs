// Tapscript

// use super::{
//     checksum::{desc_checksum, verify_checksum},
//     DescriptorTrait,
// };
use bitcoin::hashes::_export::_core::fmt::Formatter;
use errstr;
use expression::{self, FromTree, Tree};
use std::sync::Arc;
use std::{fmt, str::FromStr};
use Segwitv0;
use MAX_RECURSION_DEPTH;
use {miniscript::Miniscript, Error, MiniscriptKey};

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum TapTree<Pk: MiniscriptKey> {
    Tree(Arc<TapTree<Pk>>, Arc<TapTree<Pk>>),
    Miniscript_(Arc<Miniscript<Pk, Segwitv0>>),
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct Tr<Pk: MiniscriptKey> {
    key_path: Pk,
    script_path: Option<TapTree<Pk>>,
}

impl<Pk: MiniscriptKey> TapTree<Pk>
where
    Pk: MiniscriptKey + FromStr,
    Pk::Hash: FromStr,
    <Pk as FromStr>::Err: ToString,
    <<Pk as MiniscriptKey>::Hash as FromStr>::Err: ToString,
{
    pub fn to_string_no_checksum(&self) -> String {
        match self {
            TapTree::Tree(ref left, ref right) => {
                format!("{{{},{}}}", *left.clone(), *right.clone())
            }
            TapTree::Miniscript_(ref script) => format!("{}", *script.clone()),
        }
    }
}

impl<Pk: MiniscriptKey> fmt::Display for TapTree<Pk>
where
    Pk: MiniscriptKey + FromStr,
    Pk::Hash: FromStr,
    <Pk as FromStr>::Err: ToString,
    <<Pk as MiniscriptKey>::Hash as FromStr>::Err: ToString,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let desc = self.to_string_no_checksum();
        // let checksum = desc_checksum(&desc).map_err(|_| fmt::Error)?;
        // write!(f, "{}#{}", &desc, &checksum)
        write!(f, "{}", &desc)
    }
}

impl<Pk: MiniscriptKey> Tr<Pk>
where
    Pk: MiniscriptKey + FromStr,
    Pk::Hash: FromStr,
    <Pk as FromStr>::Err: ToString,
    <<Pk as MiniscriptKey>::Hash as FromStr>::Err: ToString,
{
    pub fn new(key_path: Pk, script_path: Option<TapTree<Pk>>) -> Result<Self, Error> {
        Ok(Tr {
            key_path,
            script_path,
        })
    }

    fn parse_miniscript(script: &str) -> Result<Miniscript<Pk, Segwitv0>, Error> {
        let (ref script_tree, rest) = Tree::from_slice(script)?;
        if rest.is_empty() {
            Miniscript::<Pk, Segwitv0>::from_tree(script_tree)
        } else {
            return Err(Error::Unexpected(format!(
                "error parsing miniscript from tapscript"
            )));
        }
    }

    // helper function for semantic parsing of script paths
    pub fn tr_script_path(tree: &Tree) -> Result<TapTree<Pk>, Error> {
        match tree {
            Tree { name, args } if name.len() > 0 && args.len() == 0 => {
                // children nodes
                let script = name;
                // Sanity checks
                let script = Self::parse_miniscript(script)?;
                let script = Arc::new(script);
                Ok(TapTree::Miniscript_(script))
            }
            Tree { name, args } if name.len() == 0 && args.len() == 2 => {
                // visit children
                let left_branch = &args[0];
                let right_branch = &args[1];
                let left_tree = Self::tr_script_path(&left_branch)?;
                let right_tree = Self::tr_script_path(&right_branch)?;
                let left_ref = Arc::new(left_tree);
                let right_ref = Arc::new(right_tree);
                Ok(TapTree::Tree(left_ref, right_ref))
            }
            _ => {
                return Err(Error::Unexpected(
                    "unknown format for script spending paths while parsing taproot descriptor"
                        .to_string(),
                ));
            }
        }
    }
}

impl<Pk: MiniscriptKey> FromTree for Tr<Pk>
where
    Pk: MiniscriptKey + FromStr,
    Pk::Hash: FromStr,
    <Pk as FromStr>::Err: ToString,
    <<Pk as MiniscriptKey>::Hash as FromStr>::Err: ToString,
{
    fn from_tree(top: &Tree) -> Result<Self, Error> {
        if top.name == "tr" {
            match top.args.len() {
                1 => {
                    let key = &top.args[0];
                    if key.args.len() > 0 {
                        return Err(Error::Unexpected(format!(
                            "#{} script associated with `key-path` while parsing taproot descriptor",
                            key.args.len()
                        )));
                    }
                    Ok(Tr {
                        key_path: expression::terminal(key, Pk::from_str)?,
                        script_path: None,
                    })
                }
                2 => {
                    let ref key = top.args[0];
                    if key.args.len() > 0 {
                        return Err(Error::Unexpected(format!(
                            "#{} script associated with `key-path` while parsing taproot descriptor",
                            key.args.len()
                        )));
                    }
                    let ref tree = top.args[1];
                    let ret = Tr::tr_script_path(tree)?;
                    Ok(Tr {
                        key_path: expression::terminal(key, Pk::from_str)?,
                        script_path: Some(ret),
                    })
                }
                _ => {
                    return Err(Error::Unexpected(format!(
                        "{}[#{} args] while parsing taproot descriptor",
                        top.name,
                        top.args.len()
                    )));
                }
            }
        } else {
            return Err(Error::Unexpected(format!(
                "{}[#{} args] while parsing taproot descriptor",
                top.name,
                top.args.len()
            )));
        }
    }
}

impl<Pk: MiniscriptKey> FromStr for Tr<Pk>
where
    Pk: MiniscriptKey + FromStr,
    Pk::Hash: FromStr,
    <Pk as FromStr>::Err: ToString,
    <<Pk as MiniscriptKey>::Hash as FromStr>::Err: ToString,
{
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // let desc_str = verify_checksum(s)?;
        // let top = expression::Tree::from_str(desc_str)?;

        // Pass the TapTree then
        let top = parse_tr(s)?;
        Self::from_tree(&top) // parse taptree and tapscript differently
    }
}

impl<Pk: MiniscriptKey> fmt::Display for Tr<Pk>
where
    Pk: MiniscriptKey + FromStr,
    Pk::Hash: FromStr,
    <Pk as FromStr>::Err: ToString,
    <<Pk as MiniscriptKey>::Hash as FromStr>::Err: ToString,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let key = &self.key_path;
        match self.script_path {
            Some(ref s) => write!(f, "tr({},{})", key, s),
            None => write!(f, "tr({})", key),
        }
    }
}

/// TODO: Refactor to make from_str more generic in `expression.rs`?
fn parse_tr<'a>(s: &'a str) -> Result<Tree<'a>, Error> {
    for ch in s.bytes() {
        if ch > 0x7f {
            return Err(Error::Unprintable(ch));
        }
    }

    let (top, rem) = parse_tr_helper(s, 0)?;
    if rem.is_empty() {
        Ok(top)
    } else {
        Err(errstr(rem))
    }
}

/// Helper function to parse Taproot Descriptor into key_path and TapTree
fn parse_tr_helper<'a>(mut sl: &'a str, depth: u32) -> Result<(Tree<'a>, &'a str), Error> {
    if depth >= MAX_RECURSION_DEPTH {
        return Err(Error::MaxRecursiveDepthExceeded);
    }

    enum Found {
        Nothing,
        Lparen(usize),
        Comma(usize),
        Rparen(usize),
    }

    let mut found = Found::Nothing;
    for (n, ch) in sl.char_indices() {
        match ch {
            '(' => {
                found = Found::Lparen(n);
                break;
            }
            ',' => {
                found = Found::Comma(n);
                break;
            }
            ')' => {
                found = Found::Rparen(n);
                break;
            }
            _ => {}
        }
    }

    match found {
        // String-ending terminal
        Found::Nothing => Ok((
            Tree {
                name: &sl[..],
                args: vec![],
            },
            "",
        )),
        // Terminal
        Found::Comma(n) | Found::Rparen(n) => Ok((
            Tree {
                name: &sl[..n],
                args: vec![],
            },
            &sl[n..],
        )),
        // Function call
        Found::Lparen(n) => {
            let mut ret = Tree {
                name: &sl[..n],
                args: vec![],
            };

            sl = &sl[n + 1..];
            let mut prev_sl: &str = "";
            let mut prev_arg: Tree;
            loop {
                if prev_sl.contains("{") {
                    let (arg, new_sl) = expression::Tree::from_slice_helper_curly(sl, depth + 1)?;
                    prev_arg = arg;
                    prev_sl = new_sl;
                } else {
                    let (arg, new_sl) = parse_tr_helper(sl, depth + 1)?;
                    prev_arg = arg;
                    prev_sl = new_sl;
                }
                ret.args.push(prev_arg);

                if prev_sl.is_empty() {
                    return Err(Error::ExpectedChar(')'));
                }

                sl = &prev_sl[1..];
                match prev_sl.as_bytes()[0] {
                    b',' => {}
                    b')' => break,
                    _ => return Err(Error::ExpectedChar(')')),
                }
            }
            Ok((ret, sl))
        }
    }
}
