// Tapscript

use crate::policy::semantic::Policy;
use crate::policy::Liftable;
use crate::util::{varint_len, witness_size, MsKeyBuilder};
use crate::{DescriptorTrait, ForEach, ForEachKey, Satisfier, ToPublicKey, TranslatePk};

use super::checksum::{desc_checksum, verify_checksum};
use bitcoin::blockdata::opcodes;
use bitcoin::hashes::_export::_core::fmt::Formatter;
use bitcoin::schnorr::TapTweak;
use bitcoin::util::taproot::TAPROOT_CONTROL_NODE_SIZE;
use bitcoin::util::taproot::{
    LeafVersion, TaprootBuilder, TaprootBuilderError, TaprootSpendInfo, TAPROOT_CONTROL_BASE_SIZE,
};
use bitcoin::{secp256k1, Script};
use errstr;
use expression::{self, FromTree, Tree};
use miniscript::{limits::TAPROOT_MAX_NODE_COUNT, Miniscript};
use std::cmp::{self, max};
use std::sync::Arc;
use std::{fmt, str::FromStr};
use Tap;
use {Error, MiniscriptKey};

/// A Taproot Tree representation.
// Hidden leaves are not yet supported in descriptor spec. Conceptually, it should
// be simple to integrate those here, but it is best to wait on core for the exact syntax.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum TapTree<Pk: MiniscriptKey> {
    /// A taproot tree structure
    Tree(Arc<TapTree<Pk>>, Arc<TapTree<Pk>>),
    /// A taproot leaf denoting a spending condition
    // A new leaf version would require a new Context, therefore there is no point
    // in adding a LeafVersion with Leaf type here. All Miniscripts right now
    // are of Leafversion::default
    Leaf(Arc<Miniscript<Pk, Tap>>),
}

/// A taproot descriptor
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct Tr<Pk: MiniscriptKey> {
    /// A taproot internal key
    internal_key: Pk,
    /// Optional Taproot Tree with spending conditions
    tree: Option<TapTree<Pk>>,
    /// Optional spending information associated with the descriptor
    /// This will be [`None`] when the descriptor is not derived.
    /// Before calling any methods that require generating address, this should
    /// be computed by calling `[Tr::spend_info]`
    spend_info: Option<TaprootSpendInfo>,
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
            TapTree::Leaf(..) => 1,
        }
    }

    /// Iterate over all miniscripts
    pub fn iter(&self) -> TapTreeIter<Pk> {
        TapTreeIter { stack: vec![self] }
    }

    // Helper function to translate keys
    fn translate_helper<FPk, FPkh, Q, Error>(
        &self,
        translatefpk: &mut FPk,
        translatefpkh: &mut FPkh,
    ) -> Result<TapTree<Q>, Error>
    where
        FPk: FnMut(&Pk) -> Result<Q, Error>,
        FPkh: FnMut(&Pk::Hash) -> Result<Q::Hash, Error>,
        Q: MiniscriptKey,
    {
        let frag = match self {
            TapTree::Tree(l, r) => TapTree::Tree(
                Arc::new(l.translate_helper(translatefpk, translatefpkh)?),
                Arc::new(r.translate_helper(translatefpk, translatefpkh)?),
            ),
            TapTree::Leaf(ms) => {
                TapTree::Leaf(Arc::new(ms.translate_pk(translatefpk, translatefpkh)?))
            }
        };
        Ok(frag)
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

impl<Pk: MiniscriptKey> fmt::Debug for TapTree<Pk> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            TapTree::Tree(ref left, ref right) => write!(f, "{{{:?},{:?}}}", *left, *right),
            TapTree::Leaf(ref script) => write!(f, "{:?}", *script),
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
            Ok(Self {
                internal_key,
                tree,
                spend_info: None,
            })
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

    /// Compute the [`TaprootSpendInfo`] associated with this descriptor if spend data is [None]
    /// If spend data is already computed (i.e it is not None), this does not recompute it
    /// TaprootSpendInfo is only required for spending via the script paths.
    pub fn spend_info<C: secp256k1::Verification>(
        &mut self,
        secp: &secp256k1::Secp256k1<C>,
    ) -> &TaprootSpendInfo
    where
        Pk: ToPublicKey,
    {
        // Already computed cache
        if let Some(ref info) = self.spend_info {
            return info;
        } else {
            // Key spend path with no merkle root
            if self.tree.is_none() {
                let data = TaprootSpendInfo::new_key_spend(
                    secp,
                    self.internal_key.to_x_only_pubkey(),
                    None,
                );
                self.spend_info = Some(data);
                return self.spend_info.as_ref().unwrap();
            }
            let mut builder = TaprootBuilder::new();
            for (depth, ms) in self.iter_scripts() {
                let script = ms.encode();
                builder = builder
                    .add_leaf(depth, script)
                    .expect("Computing spend data on a valid Tree should always succeed");
            }
            // Assert builder cannot error here
            let data = match builder.finalize(secp, self.internal_key.to_x_only_pubkey()) {
                Ok(data) => data,
                Err(e) => match e {
                    TaprootBuilderError::InvalidMerkleTreeDepth(_) => {
                        unreachable!("Depth checked in struct construction")
                    }
                    TaprootBuilderError::NodeNotInDfsOrder => {
                        unreachable!("Insertion is called in DFS order")
                    }
                    TaprootBuilderError::OverCompleteTree => {
                        unreachable!("Taptree is a well formed tree")
                    }
                    TaprootBuilderError::InvalidInternalKey(_) => {
                        unreachable!("Internal key checked for validity")
                    }
                    TaprootBuilderError::IncompleteTree => {
                        unreachable!("Taptree is a well formed tree")
                    }
                    TaprootBuilderError::EmptyTree => {
                        unreachable!("Taptree is a well formed tree with atleast 1 element")
                    }
                    TaprootBuilderError::ScriptWeightOverflow => unreachable!(),
                },
            };
            // Add the data
            self.spend_info = Some(data);
            return &self.spend_info.as_ref().unwrap();
        }
    }
}

impl<Pk: MiniscriptKey + ToPublicKey> Tr<Pk> {
    /// Obtain the corresponding script pubkey for this descriptor
    /// Same as[`DescriptorTrait::script_pubkey`] for this descriptor
    pub fn spk(&self) -> Result<Script, Error> {
        let spend_info = self
            .spend_info
            .as_ref()
            .ok_or(Error::TaprootSpendInfoUnavialable)?;
        let output_key = spend_info.output_key();
        let builder = bitcoin::blockdata::script::Builder::new();
        Ok(builder
            .push_opcode(opcodes::all::OP_PUSHNUM_1)
            .push_ms_key::<_, Tap>(&output_key)
            .into_script())
    }

    /// Obtain the corresponding script pubkey for this descriptor
    /// Same as[`DescriptorTrait::address`] for this descriptor
    pub fn addr(&self, network: bitcoin::Network) -> Result<bitcoin::Address, Error> {
        let spend_info = self
            .spend_info
            .as_ref()
            .ok_or(Error::TaprootSpendInfoUnavialable)?;
        Ok(bitcoin::Address::p2tr_tweaked(
            TapTweak::dangerous_assume_tweaked(spend_info.output_key()),
            network,
        ))
    }
}

/// Iterator for Taproot structures
/// Yields a pair of (depth, miniscript) in a depth first walk
/// For example, this tree:
///                                     - N0 -
///                                    /     \\
///                                   N1      N2
///                                  /  \    /  \\
///                                 A    B  C   N3
///                                            /  \\
///                                           D    E
/// would yield (2, A), (2, B), (2,C), (3, D), (3, E).
///
#[derive(Debug, Clone)]
pub struct TapTreeIter<'a, Pk: MiniscriptKey>
where
    Pk: 'a,
{
    stack: Vec<&'a TapTree<Pk>>,
}

impl<'a, Pk> Iterator for TapTreeIter<'a, Pk>
where
    Pk: MiniscriptKey + 'a,
{
    type Item = (usize, &'a Miniscript<Pk, Tap>);

    fn next(&mut self) -> Option<Self::Item> {
        while !self.stack.is_empty() {
            let last = self.stack.pop().expect("Size checked above");
            match &*last {
                TapTree::Tree(l, r) => {
                    self.stack.push(&r);
                    self.stack.push(&l);
                }
                TapTree::Leaf(ref ms) => return Some((self.stack.len(), ms)),
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
                        spend_info: None,
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
                        spend_info: None,
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

impl<Pk: MiniscriptKey> fmt::Debug for Tr<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.tree {
            Some(ref s) => write!(f, "tr({:?},{:?})", self.internal_key, s),
            None => write!(f, "tr({:?})", self.internal_key),
        }
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

impl<Pk: MiniscriptKey> Liftable<Pk> for TapTree<Pk> {
    fn lift(&self) -> Result<Policy<Pk>, Error> {
        fn lift_helper<Pk: MiniscriptKey>(s: &TapTree<Pk>) -> Result<Policy<Pk>, Error> {
            match s {
                TapTree::Tree(ref l, ref r) => {
                    Ok(Policy::Threshold(1, vec![lift_helper(l)?, lift_helper(r)?]))
                }
                TapTree::Leaf(ref leaf) => leaf.lift(),
            }
        }

        let pol = lift_helper(&self)?;
        Ok(pol.normalized())
    }
}

impl<Pk: MiniscriptKey> Liftable<Pk> for Tr<Pk> {
    fn lift(&self) -> Result<Policy<Pk>, Error> {
        match &self.tree {
            Some(root) => root.lift(),
            None => Ok(Policy::KeyHash(self.internal_key.to_pubkeyhash())),
        }
    }
}

impl<Pk: MiniscriptKey> DescriptorTrait<Pk> for Tr<Pk> {
    fn sanity_check(&self) -> Result<(), Error> {
        for (_depth, ms) in self.iter_scripts() {
            ms.sanity_check()?;
        }
        Ok(())
    }

    fn address(&self, network: bitcoin::Network) -> Result<bitcoin::Address, Error>
    where
        Pk: ToPublicKey,
    {
        self.addr(network)
    }

    fn script_pubkey(&self) -> Result<Script, Error>
    where
        Pk: ToPublicKey,
    {
        self.spk()
    }

    fn unsigned_script_sig(&self) -> Script
    where
        Pk: ToPublicKey,
    {
        Script::new()
    }

    fn explicit_script(&self) -> Result<Script, Error>
    where
        Pk: ToPublicKey,
    {
        self.script_pubkey()
    }

    fn get_satisfaction<S>(&self, satisfier: S) -> Result<(Vec<Vec<u8>>, Script), Error>
    where
        Pk: ToPublicKey,
        S: Satisfier<Pk>,
    {
        let spend_info = self
            .spend_info
            .as_ref()
            .ok_or(Error::TaprootSpendInfoUnavialable)?;
        // First try the key spend path
        if let Some(sig) = satisfier.lookup_tap_key_spend_sig() {
            Ok((vec![sig.serialize()], Script::new()))
        } else {
            // try script spend
            // Since we have the complete descriptor we can ignore the satisfier. We don't use the control block
            // map (lookup_control_block) from the satisfier here.
            let (mut min_wit, mut min_wit_len) = (None, None);
            for (depth, ms) in self.iter_scripts() {
                let mut wit = match ms.satisfy(&satisfier) {
                    Ok(wit) => wit,
                    Err(..) => continue, // No witness for this script in tr descriptor, look for next one
                };
                // Compute the final witness size
                // Control block len + script len + witnesssize + varint(wit.len + 2)
                // The extra +2 elements are control block and script itself
                let wit_size = witness_size(&wit)
                    + control_block_len(depth)
                    + ms.script_size()
                    + varint_len(ms.script_size());
                if min_wit_len.is_some() && Some(wit_size) > min_wit_len {
                    continue;
                } else {
                    let ver = LeafVersion::default();
                    let leaf_script = (ms.encode(), ver);
                    let control_block_set = spend_info
                        .as_script_map()
                        .get(&leaf_script)
                        .expect("Control block must exist in script map for every known leaf");
                    wit.push(leaf_script.0.into_bytes()); // Push the leaf script
                                                          // There can be multiple control blocks for a (script, ver) pair
                                                          // Find the smallest one amongst those
                    let control_block = control_block_set
                        .iter()
                        .min_by(|x, y| x.as_inner().len().cmp(&y.as_inner().len()))
                        .expect("Atleast one control must exist for a known leaf");
                    wit.push(control_block.serialize());
                    // Finally, save the minimum
                    min_wit = Some(wit);
                    min_wit_len = Some(wit_size);
                }
            }
            match min_wit {
                Some(wit) => Ok((wit, Script::new())),
                None => Err(Error::CouldNotSatisfy), // Could not satisfy all miniscripts inside Tr
            }
        }
    }

    fn max_satisfaction_weight(&self) -> Result<usize, Error> {
        let mut max_wieght = None;
        for (depth, ms) in self.iter_scripts() {
            let script_size = ms.script_size();
            let max_sat_elems = match ms.max_satisfaction_witness_elements() {
                Ok(elem) => elem,
                Err(..) => continue,
            };
            let max_sat_size = match ms.max_satisfaction_size() {
                Ok(sz) => sz,
                Err(..) => continue,
            };
            let control_block_sz = control_block_len(depth);
            let wit_size = 4 + // scriptSig len byte
            control_block_sz + // first element control block
            varint_len(script_size) +
            script_size + // second element script len with prefix
            varint_len(max_sat_elems) +
            max_sat_size; // witness
            max_wieght = cmp::max(max_wieght, Some(wit_size));
        }
        max_wieght.ok_or(Error::ImpossibleSatisfaction)
    }

    fn script_code(&self) -> Result<Script, Error>
    where
        Pk: ToPublicKey,
    {
        Err(Error::TrNoScriptCode)
    }
}

impl<Pk: MiniscriptKey> ForEachKey<Pk> for Tr<Pk> {
    fn for_each_key<'a, F: FnMut(ForEach<'a, Pk>) -> bool>(&'a self, mut pred: F) -> bool
    where
        Pk: 'a,
        Pk::Hash: 'a,
    {
        let script_keys_res = self
            .iter_scripts()
            .all(|(_d, ms)| ms.for_any_key(&mut pred));
        script_keys_res && pred(ForEach::Key(&self.internal_key))
    }
}

impl<P: MiniscriptKey, Q: MiniscriptKey> TranslatePk<P, Q> for Tr<P> {
    type Output = Tr<Q>;

    fn translate_pk<Fpk, Fpkh, E>(
        &self,
        mut translatefpk: Fpk,
        mut translatefpkh: Fpkh,
    ) -> Result<Self::Output, E>
    where
        Fpk: FnMut(&P) -> Result<Q, E>,
        Fpkh: FnMut(&P::Hash) -> Result<Q::Hash, E>,
        Q: MiniscriptKey,
    {
        let translate_desc = Tr {
            internal_key: translatefpk(&self.internal_key)?,
            tree: match &self.tree {
                Some(tree) => Some(tree.translate_helper(&mut translatefpk, &mut translatefpkh)?),
                None => None,
            },
            spend_info: self.spend_info.clone(),
        };
        Ok(translate_desc)
    }
}

// Helper function to compute the len of control block at a given depth
fn control_block_len(depth: usize) -> usize {
    TAPROOT_CONTROL_BASE_SIZE + depth * TAPROOT_CONTROL_NODE_SIZE
}
