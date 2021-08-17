// Tapscript

use std::{fmt, str::FromStr};
use std::sync::Arc;
use bitcoin::{self, Script};

use expression::{self, FromTree, Tree};
use miniscript::context::{ScriptContext, ScriptContextError};
use policy::{semantic, Liftable};
use util::varint_len;
use {
    Error, ForEach, ForEachKey, Miniscript, MiniscriptKey, Satisfier, ToPublicKey, TranslatePk,
};
use miniscript::Miniscript;
use super::{
    checksum::{desc_checksum, verify_checksum},
    DescriptorTrait,
};
use Segwitv0;

// #[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
// pub struct TapBranch<Pk> {
//     left_child: TapChild<Pk>,
//     right_child: TapChild<Pk>,
// }

// #[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
// pub struct TapLeaf<Pk> {
//     ver: u8,
//     size: u32,
//     script: MiniscriptKey,
// }

// #[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
// pub enum TapChild<Pk> {
//     Branch(TapBranch<Pk>),
//     Leaf(TapLeaf<Pk>),
// }

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum TapTree<Pk: MiniscriptKey> {
     Tree((Arc<Taptree<Pk>>, Arc<TapChild<Pk>>)),
     Miniscript_((u8, Miniscript<Pk, Segwitv0>)) // TODO;
}

// Store Ts with a
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct Tr<Pk: MiniscriptKey> {
    key_path: Pk,
    script_path: TapTree<Pk>,
}

impl<Pk> FromTree for Tr<Pk>
where 
    Pk: MiniscriptKey + FromStr,
    Pk::Hash: FromStr,
    <Pk as FromStr>::Err: ToString,
    <<Pk as MiniscriptKey>::Hash as FromStr>::Err: ToString,
{
    fn from_tree(top: &Tree) -> Result<Self, Error> {
        todo!(Parse a given tree into TapTree)
    }
}

impl<Pk> FromStr for Ts<Pk>
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

impl<Pk: MiniscriptKey> fmt::Display for Ts<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let desc = self.to_string_no_checksum();
        todo!(Inorder traversal and printing it back)
    }
}