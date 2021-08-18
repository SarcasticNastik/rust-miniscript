// Tapscript

use super::{
    checksum::{desc_checksum, verify_checksum},
    DescriptorTrait,
};
use expression::{self, FromTree, Tree};
use miniscript::context::{ScriptContext, ScriptContextError};
use policy::{semantic, Liftable};
use std::sync::Arc;
use std::{fmt, str::FromStr};
use util::varint_len;
use Segwitv0;
use {
    miniscript::Miniscript, Error, ForEach, ForEachKey, MiniscriptKey, Satisfier, ToPublicKey,
    TranslatePk,
};

// temporary stub version
const VER: u8 = 1;

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum TapTree<Pk: MiniscriptKey> {
    Tree(Arc<TapTree<Pk>>, Arc<TapTree<Pk>>),
    // TODO: 1. Should we keep the name as miniscript and change the name?
    // 2. Why no ARC?
    Miniscript_(u8, Arc<Miniscript<Pk, Segwitv0>>),
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct Tr<Pk: MiniscriptKey> {
    key_path: Pk,
    script_path: TapTree<Pk>,
}

impl<Pk: MiniscriptKey> TapTree<Pk> {
    pub fn new(value: Option<Pk>) -> Result<Self, Error> {
        todo!();
    }
}

impl<Pk: MiniscriptKey> Tr<Pk> {
    pub fn new(key_path: Pk, script_path: TapTree<Pk>) -> Result<Self, Error> {
        // TODO: Sanity checks
        Ok((Tr {
            key_path,
            script_path,
        }))
    }

    fn parse_miniscript(script: &str) -> Result<Miniscript<Pk, Segwitv0>, Error> {
        let (ref script_tree, rest) = Tree::from_slice(script)?;
        if rest.is_empty() {
            Miniscript::<Pk, Segwitv0>::from_tree(script_tree)
        }
        else {
            return Err(Error::Unexpected(format!(
               "incomplete syntactic parsing of miniscript occured"
            )));
        }
    }

    // helper function for semantic parsing of script paths
    pub fn tr_script_path(tree: &Tree) -> Result<TapTree<Pk>, Error> {
        match tree {
            Tree {
                name,
                args,
            } if name.len() > 0 && args.len() == 0 => {
                // children nodes
                let script = name;
                // Sanity checks
                let script = Self::parse_miniscript(script)?;
                let script = Arc::new(script);
                Ok(TapTree::Miniscript_(VER, script))
            },
            Tree {
                name,
                args,
            } if name.len() == 0 && args.len() == 2 => {
                // visit children
                let left_branch = args.0;
                let right_branch = args.1;
                let left_tree = Self::tr_script_path(left_branch)?;
                let right_tree = Self::tr_script_path(right_branch)?;
                let left_ref = Arc::new(left_tree);
                let right_ref = Arc::new(right_tree);
                Ok(TapTree::Tree(left_ref, right_ref))
            }
            _ => {
                return Err(Error::Unexpected(
                    "unknown format for script spending paths while parsing taproot descriptor"
                        .to_str(),
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
                    let key = top.args.0; // have key checks here
                    if key.args.len() {
                        return Err(Error::Unexpected(format!(
                        "#{} script associated with `key-path` while parsing taproot descriptor",
                        key.args.len()
                        )));
                    }
                    Ok(Tr {
                        key_path: key.to_string(),
                        script_path: TapTree::Miniscript_(0, Taptree::Miniscript_((0, 0))), // What to specify here?
                    })
                }
                2 => {
                    let key = top.args.0; // have key checks here
                    if key.args.len() {
                        return Err(Error::Unexpected(format!(
                            "#{} script associated with `key-path` while parsing taproot descriptor",
                            key.args.len()
                        )));
                    }
                    let tree = top.args.1; // Tree name should be a valid miniscript except the base case
                    let ret = Tr::tr_script_path(tree)?;
                    Ok(Tr {
                        key_path: key,
                        script_path: ret,
                    })
                }
                _ => {
                    return Err(Error::Unexpected(format!(
                        "{}({} args) while parsing taproot descriptor",
                        top.name,
                        top.args.len()
                    )))
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
        let desc_str = verify_checksum(s)?;
        let top = expression::Tree::from_str(desc_str)?;
        Self::from_tree(&top)
    }
}

impl<Pk: MiniscriptKey> fmt::Display for Tr<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // let desc = self.to_string_no_checksum();
        todo!("Inorder traversal and printing it back");
    }
}
