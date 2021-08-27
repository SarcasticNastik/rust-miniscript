// Tapscript

// use super::{
//     checksum::{desc_checksum, verify_checksum},
//     DescriptorTrait,
// };
use bitcoin::hashes::_export::_core::fmt::Formatter;
use expression::{self, FromTree, Tree};
use std::sync::Arc;
use std::{fmt, str::FromStr};
use Segwitv0;
use {miniscript::Miniscript, Error, MiniscriptKey};

// TODO: Update this to infer version from descriptor.
const VER: u8 = 0xc0;

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum TapTree<Pk: MiniscriptKey> {
    Tree(Arc<TapTree<Pk>>, Arc<TapTree<Pk>>),
    Miniscript_(u8, Arc<Miniscript<Pk, Segwitv0>>),
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
            TapTree::Tree(ref left, ref right) => format!("{{{},{}}}", *left, *right),
            TapTree::Miniscript_(_, ref miniscript) => format!("{}", *miniscript),
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
        // write!(f, "{}", &desc)
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
                Ok(TapTree::Miniscript_(VER, script))
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

impl<Pk> FromTree for Tr<Pk>
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
                    let ref tree = top.args[1]; // Tree name should be a valid miniscript except the base case
                    let ret = Tr::tr_script_path(&tree)?;
                    Ok(Tr {
                        key_path: expression::terminal(key, Pk::from_str)?,
                        script_path: Some(ret),
                    })
                }
                _ => {
                    return Err(Error::Unexpected(format!(
                        "{}({} args) while parsing taproot descriptor",
                        top.name,
                        top.args.len()
                    )));
                }
            }
        } else {
            return Err(Error::Unexpected(format!(
                "{}({} args) while parsing taproot descriptor",
                top.name,
                top.args.len()
            )));
        }
    }
}

impl<Pk> FromStr for Tr<Pk>
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
        let top = expression::Tree::from_str(s)?;
        Self::from_tree(&top)
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
        match self.script_path {
            Some(ref s) => write!(f, "tr({},{})", self.key_path, s),
            None => write!(f, "tr({})", self.key_path),
        }
    }
}
