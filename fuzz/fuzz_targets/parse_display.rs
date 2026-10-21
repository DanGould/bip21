//! Any string that parses is displayed back unchanged, and its alternate
//! `{:#}` form parses to the same `Uri`.

#![no_main]

use bitcoin_uri::Uri;
use libfuzzer_sys::fuzz_target;

fn check(input: &str) {
    let Ok(uri) = Uri::parse(input) else { return };
    let uri = uri.assume_checked();
    assert_eq!(uri.to_string(), input);

    let alternate = format!("{:#}", uri);
    let reparsed = Uri::parse(&alternate).unwrap_or_else(|e| panic!("{:?} should parse: {:?}", alternate, e));
    assert_eq!(reparsed.assume_checked(), uri, "{:?}", alternate);
}

fuzz_target!(|input: &str| {
    check(input);
    // Random input rarely starts with the scheme, so also try it with one.
    check(&format!("bitcoin:{}", input));
});
