extern crate miniscript;

use miniscript::policy;
#[cfg(feature = "compiler")]
use miniscript::policy::Concrete;
use std::str::FromStr;

fn main() {
    let unspendable_key = "UNSPENDABLE".to_string();
    let examples_str = vec![
        "or(pk(A),pk(B))",
        "or(and(pk(A),pk(B)),pk(C))",
        "or(9@or(10@or(1@pk(A),100@pk(D)),1@pk(B)),1@pk(C))",
        "or(or(or(pk(A),pk(D)),pk(B)),pk(C))",
        "or(1@pk(A),1@or(1@and(pk(B),pk(C)),1@and(pk(D),older(10))))",
        "thresh(1,or(pk(A),pk(B)),or(pk(C),or(and(pk(E),pk(F)),pk(D))))",
        "thresh(1,pk(Z),and(pk(A),or(pk(B),pk(C))),pk(D),or(or(pk(G),pk(E)),and(pk(F),pk(X))))",
        "thresh(1,and(pk(A),or(pk(B),pk(C))),or(10@pk(D),7@pk(E)),or(2@or(pk(F),and(pk(G),pk(H))),7@pk(I)))",
    ];
    let examples_pol: Vec<Concrete<String>> = examples_str
        .into_iter()
        .map(|s| policy::Concrete::from_str(s).unwrap())
        .collect();
    let mut i: usize = 1;
    for pol in examples_pol {
        println!("Example {}\npolicy: {}", i, pol);
        i += 1;
        let comp_eff = pol.compile_tr(Some(unspendable_key.clone()), true).unwrap();
        let comp_priv = pol
            .compile_tr(Some(unspendable_key.clone()), false)
            .unwrap();
        println!(
            "Private compilation: {}\nEfficient compilation: {}\n",
            comp_priv, comp_eff
        );
    }
}
