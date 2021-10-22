// Tapscript

use super::checksum::{desc_checksum, verify_checksum};
use bitcoin::hashes::_export::_core::fmt::Formatter;
use errstr;
use expression::{self, FromTree, Tree};
use miniscript::{limits::TAPROOT_MAX_NODE_COUNT, Miniscript};
use std::cmp::max;
use std::sync::Arc;
use std::{fmt, str::FromStr};
use Tap;
use {Error, MiniscriptKey};

/// A Taproot Tree representation.
// Hidden leaves are not yet supported in descriptor spec. Conceptually, it should
// be simple to integrate those here, but it is best to wait on core for the exact syntax.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub enum TapTree<Pk: MiniscriptKey> {
    /// A taproot tree structure
    Tree(Arc<TapTree<Pk>>, Arc<TapTree<Pk>>),
    /// A taproot leaf denoting a spending condition
    Leaf(Arc<Miniscript<Pk, Tap>>),
}

/// A taproot descriptor
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct Tr<Pk: MiniscriptKey> {
    /// A taproot internal key
    internal_key: Pk,
    /// Optional Taproot Tree with spending conditions
    tree: Option<TapTree<Pk>>,
}

impl<Pk: MiniscriptKey> TapTree<Pk> {
    // Helper function to compute height
    // TODO: Instead of computing this every time we add a new leaf, we should
    // add height as a separate field in taptree
    fn taptree_height(&self) -> usize {
        match *self {
            TapTree::Tree(ref left_tree, ref right_tree) => {
                1 + max(left_tree.taptree_height(), right_tree.taptree_height())
            }
            TapTree::Leaf(_) => 1,
        }
    }

    /// Iterate over all miniscripts
    pub fn iter(&self) -> TapTreeIter<Pk> {
        TapTreeIter { stack: vec![self] }
    }
}

impl<Pk: MiniscriptKey> fmt::Display for TapTree<Pk> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            TapTree::Tree(ref left, ref right) => write!(f, "{{{},{}}}", *left, *right),
            TapTree::Leaf(ref script) => write!(f, "{}", *script),
        }
    }
}

impl<Pk: MiniscriptKey> Tr<Pk> {
    /// Create a new [`Tr`] descriptor from internal key and [`TapTree`]
    pub fn new(internal_key: Pk, tree: Option<TapTree<Pk>>) -> Result<Self, Error> {
        let nodes = match tree {
            Some(ref t) => t.taptree_height(),
            None => 0,
        };

        if nodes <= TAPROOT_MAX_NODE_COUNT {
            Ok(Self { internal_key, tree })
        } else {
            Err(Error::MaxRecursiveDepthExceeded)
        }
    }

    fn to_string_no_checksum(&self) -> String {
        let key = &self.internal_key;
        match self.tree {
            Some(ref s) => format!("tr({},{})", key, s),
            None => format!("tr({})", key),
        }
    }

    /// Obtain the internal key of [`Tr`] descriptor
    pub fn internal_key(&self) -> &Pk {
        &self.internal_key
    }

    /// Obtain the [`TapTree`] of the [`Tr`] descriptor
    pub fn taptree(&self) -> &Option<TapTree<Pk>> {
        &self.tree
    }

    /// Iterate over all scripts in merkle tree. If there is no script path, the iterator
    /// yields [`None`]
    pub fn iter_scripts(&self) -> TapTreeIter<Pk> {
        match self.tree {
            Some(ref t) => t.iter(),
            None => TapTreeIter { stack: vec![] },
        }
    }
}

/// Iterator for Taproot structures
/// Yields the miniscript in a depth first walk
#[derive(Debug, Clone)]
pub struct TapTreeIter<'a, Pk: MiniscriptKey> where Pk: 'a {
    stack: Vec<&'a TapTree<Pk>>,
}

impl<'a, Pk> Iterator for TapTreeIter<'a, Pk>
where
    Pk: MiniscriptKey + 'a,
{
    type Item = &'a Miniscript<Pk, Tap>;

    fn next(&mut self) -> Option<Self::Item> {
        while !self.stack.is_empty() {
            let last = self.stack.pop().expect("Size checked above");
            match &*last {
                TapTree::Tree(l, r) => {
                    self.stack.push(&r);
                    self.stack.push(&l);
                }
                TapTree::Leaf(ref ms) => return Some(ms),
            }
        }
        None
    }
}

impl<Pk> Tr<Pk>
where
    Pk: MiniscriptKey + FromStr,
    Pk::Hash: FromStr,
    <Pk as FromStr>::Err: ToString,
    <<Pk as MiniscriptKey>::Hash as FromStr>::Err: ToString,
{
    // Helper function to parse taproot script path
    fn tr_script_path(tree: &Tree) -> Result<TapTree<Pk>, Error> {
        match tree {
            Tree { name, args } if name.len() > 0 && args.len() == 0 => {
                let script = Miniscript::<Pk, Tap>::from_str(name)?;
                Ok(TapTree::Leaf(Arc::new(script)))
            }
            Tree { name, args } if name.len() == 0 && args.len() == 2 => {
                let left = Self::tr_script_path(&args[0])?;
                let right = Self::tr_script_path(&args[1])?;
                Ok(TapTree::Tree(Arc::new(left), Arc::new(right)))
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
                        internal_key: expression::terminal(key, Pk::from_str)?,
                        tree: None,
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
                        internal_key: expression::terminal(key, Pk::from_str)?,
                        tree: Some(ret),
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
        let desc_str = verify_checksum(s)?;
        let top = parse_tr(desc_str)?;
        Self::from_tree(&top)
    }
}

impl<Pk: MiniscriptKey> fmt::Display for Tr<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let desc = self.to_string_no_checksum();
        let checksum = desc_checksum(&desc).map_err(|_| fmt::Error)?;
        write!(f, "{}#{}", &desc, &checksum)
    }
}

fn parse_tr(s: &str) -> Result<Tree, Error> {
    for ch in s.bytes() {
        if ch > 0x7f {
            return Err(Error::Unprintable(ch));
        }
    }

    let ret = if s.len() > 3 && &s[..3] == "tr(" && s.as_bytes()[s.len() - 1] == b')' {
        let rest = &s[3..s.len() - 1];
        if !rest.contains(',') {
            let internal_key = Tree {
                name: rest,
                args: vec![],
            };
            return Ok(Tree {
                name: "tr",
                args: vec![internal_key],
            });
        }
        // use str::split_once() method to refactor this when compiler version bumps up
        let (key, script) = split_once(rest, ',')
            .ok_or_else(|| Error::BadDescriptor("invalid taproot descriptor".to_string()))?;

        let internal_key = Tree {
            name: key,
            args: vec![],
        };
        if script.is_empty() {
            return Ok(Tree {
                name: "tr",
                args: vec![internal_key],
            });
        }
        let (tree, rest) = expression::Tree::from_slice_helper_curly(script, 1)?;
        if rest.is_empty() {
            Ok(Tree {
                name: "tr",
                args: vec![internal_key, tree],
            })
        } else {
            Err(errstr(rest))
        }
    } else {
        Err(Error::Unexpected("invalid taproot descriptor".to_string()))
    };

    return ret;
}

fn split_once(inp: &str, delim: char) -> Option<(&str, &str)> {
    let ret = if inp.len() == 0 {
        None
    } else {
        let mut found = inp.len();
        for (idx, ch) in inp.chars().enumerate() {
            if ch == delim {
                found = idx;
                break;
            }
        }
        // No comma or trailing comma found
        if found >= inp.len() - 1 {
            Some((&inp[..], ""))
        } else {
            Some((&inp[..found], &inp[found + 1..]))
        }
    };
    return ret;
}
