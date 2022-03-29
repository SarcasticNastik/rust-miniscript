extern crate miniscript;

use std::str::FromStr;
use miniscript::policy;
#[cfg(feature = "compiler")]
use miniscript::policy::Concrete;

fn main() {
    let unspendable_key = "UNSPENDABLE".to_string();
    let examples_str = vec!["or(pk(A),pk(B))", "or(and(pk(A),pk(B)),pk(C))", "thresh(1,or(pk(A),pk(B)),or(pk(C),or(and(pk(E),pk(F)),pk(D))))", "thresh(1,pk(Z),and(pk(A),or(pk(B),pk(C))),pk(D),or(or(pk(G),pk(E)),and(pk(F),pk(X))))"];
    let examples_pol: Vec<Concrete<String>> = examples_str.into_iter().map(|s| policy::Concrete::from_str(s).unwrap()).collect();
    let mut i: usize = 1;
    for pol in examples_pol {
        println!("Example {}\npolicy: {}", i, pol);
        i += 1;
        let comp = pol.compile_tr(Some(unspendable_key.clone()),true).unwrap();
        println!("miniscript compilation: {}\n" ,comp);
    }
}