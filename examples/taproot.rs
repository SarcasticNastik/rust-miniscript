extern crate bitcoin;
extern crate miniscript;

#[cfg(feature = "compiler")]
use miniscript::policy::Concrete;
use miniscript::Descriptor;
use std::str::FromStr;

fn main() {
    let policies_str = [
        "or(1@pk(A),1@pk(B))",
        "or(1@and(pk(A),pk(B)),1@pk(C))",
        "or(9@or(10@or(1@pk(A),100@pk(D)),1@pk(B)),1@pk(C))",
        "or(1@or(1@or(1@pk(A),1@pk(D)),1@pk(B)),1@pk(C))",
        "or(1@pk(A),1@or(1@and(pk(B),pk(C)),1@and(pk(D),older(10))))",
        "thresh(1,or(1@pk(A),1@pk(B)),or(1@pk(C),1@or(1@and(pk(E),pk(F)),1@pk(D))))",
        "thresh(1,pk(Z),and(pk(A),or(1@pk(B),1@pk(C))),pk(D),or(1@or(1@pk(G),1@pk(E)),1@and(pk(F),pk(X))))",
        "thresh(1,and(pk(A),or(1@pk(B),1@pk(C))),or(10@pk(D),7@pk(E)),or(2@or(1@pk(F),1@and(pk(G),pk(H))),7@pk(I)))"
    ];
    let unspendable_key = "UNSPENDABLE_KEY".to_string();
    let policies: Vec<Concrete<String>> = policies_str
        .into_iter()
        .map(|x| Concrete::from_str(x).unwrap())
        .collect();
    let private_comp: Vec<Descriptor<String>> = policies
        .iter()
        .map(|pol| {
            pol.compile_tr_private(Some(unspendable_key.clone()))
                .unwrap()
        })
        .collect();
    let default_comp: Vec<Descriptor<String>> = policies
        .iter()
        .map(|pol| pol.compile_tr(Some(unspendable_key.clone())).unwrap())
        .collect();

    for idx in 0..policies.len() {
        println!("Example {}", idx + 1);
        println!("Policy: {}", policies_str[idx]);
        println!("Private compilation: {}", private_comp[idx]);
        println!("Default compilation: {}\n", default_comp[idx]);
    }
}
