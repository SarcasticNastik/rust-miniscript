extern crate bitcoin;
extern crate miniscript;

use bitcoin::Network;
use miniscript::descriptor::Tr;
use miniscript::policy::{Concrete, Liftable};
use miniscript::{DescriptorTrait, Tap};
use std::str::FromStr;

fn main() {
    //HTLC policy with 10:1 odds for happy(co-operative) case compared to uncooperative case
    let htlc_policy = Concrete::<bitcoin::SchnorrSig>::from_str(&format!("or(10@and(sha256({secret_hash}),pk({redeem_identity})),1@and(older({expiry}),pk({refund_identity})))",
                                                                        secret_hash = "1111111111111111111111111111111111111111111111111111111111111111",
                                                                        redeem_identity = "022222222222222222222222222222222222222222222222222222222222222222",
                                                                        refund_identity = "020202020202020202020202020202020202020202020202020202020202020202",
                                                                        expiry = "4444"
    )).unwrap();

    let htlc_descriptor = htlc_policy.compile::<Tap>().expect("Resource limits");

    // Check whether the descriptor is safe
    // This checks whether all spend paths are accessible in bitcoin network.
    // It maybe possible that some of the spend require more than 100 elements in Wsh scripts
    // Or they contain a combination of timelock and heightlock.
    assert!(htlc_descriptor.sanity_check().is_ok());
    // assert_eq!(
    //     format!("{}", htlc_descriptor),
    //     "wsh(andor(pk(022222222222222222222222222222222222222222222222222222222222222222),sha256(1111111111111111111111111111111111111111111111111111111111111111),and_v(v:pkh(51814f108670aced2d77c1805ddd6634bc9d4731),older(4444))))#s0qq76ng"
    // );
    println!("descriptor: {}", htlc_descriptor);

    // assert_eq!(
    //     format!("{}", htlc_descriptor.lift().unwrap()),
    //     "or(and(pkh(4377a5acd66dc5cb67148a24818d1e51fa183bd2),sha256(1111111111111111111111111111111111111111111111111111111111111111)),and(pkh(51814f108670aced2d77c1805ddd6634bc9d4731),older(4444)))"
    // );
    println!("lifted: {}", htlc_descriptor.lift().unwrap());
}
