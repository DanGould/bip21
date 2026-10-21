//! Any `Uri` the builder produces parses back to the same `Uri`, with each
//! encoded value decoding to the text it was built from.

#![no_main]

use bitcoin::Network;
use bitcoin_uri::{Uri, UriBuilder};
use libfuzzer_sys::{arbitrary, fuzz_target};

const ADDRESSES: [&str; 3] = [
    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
    "1andreas3batLhQa2FawWjeyjCqyBzypd",
    "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
];
const NETWORKS: [Network; 3] = [Network::Bitcoin, Network::Testnet, Network::Regtest];
const HRP_KEYS: [&str; 6] = ["bc", "tb", "bcrt", "req-bc", "TB", "Req-Bcrt"];

#[derive(Debug, arbitrary::Arbitrary)]
enum Part {
    Param { key: String, value: String },
    RawParam { key: String, raw_value: String },
    // An address from `ADDRESSES` re-encoded for a network from `NETWORKS`, under a
    // key from `HRP_KEYS`, so the HRP checks see matching and mismatched
    // values.
    HrpParam { key: u8, address: u8, network: u8 },
    Label(String),
    Message(String),
    Amount(u64),
}

#[derive(Debug, arbitrary::Arbitrary)]
struct Input {
    body: Option<(u8, u8)>,
    parts: Vec<Part>,
}

fn address(index: u8, network: u8) -> bitcoin::Address {
    let address = ADDRESSES[usize::from(index) % ADDRESSES.len()];
    let script = address.parse::<bitcoin::Address<_>>().unwrap().assume_checked().script_pubkey();
    bitcoin::Address::from_script(&script, NETWORKS[usize::from(network) % NETWORKS.len()]).unwrap()
}

fuzz_target!(|input: Input| {
    let mut builder = UriBuilder::new();
    if let Some((index, network)) = input.body {
        builder = builder.address(address(index, network));
    }
    let mut decoded = Vec::new();
    for part in &input.parts {
        builder = match part {
            Part::Param { key, value } => {
                decoded.push((key.clone(), value.clone()));
                builder.param(key, value)
            },
            Part::RawParam { key, raw_value } => builder.raw_param(key, raw_value),
            Part::HrpParam {
                key,
                address: index,
                network,
            } => {
                let key = HRP_KEYS[usize::from(*key) % HRP_KEYS.len()];
                builder.param(key, &address(*index, *network).to_string())
            },
            Part::Label(label) => builder.label(label),
            Part::Message(message) => builder.message(message),
            Part::Amount(sat) => builder.amount(bitcoin::Amount::from_sat(*sat)),
        };
    }
    let Ok(built) = builder.build() else { return };

    for string in [built.to_string(), format!("{:#}", built)] {
        let reparsed = Uri::parse(&string).unwrap_or_else(|e| panic!("{:?} should parse: {:?}", string, e));
        assert_eq!(reparsed.clone().assume_checked(), built, "{:?}", string);
        assert!(
            NETWORKS.iter().any(|&network| reparsed.is_valid_for_network(network)),
            "{:?} mixes networks",
            string
        );
    }
    for (key, value) in decoded {
        // The typed setters replace an existing entry with the same key.
        if ["label", "message", "amount"].iter().any(|typed| key.eq_ignore_ascii_case(typed)) {
            continue;
        }
        // Another param with the same base key may come first in `get_all`,
        // so look for this value among all of them.
        let found = built
            .get_all(&key)
            .any(|entry| entry.decoded_value().and_then(Result::ok).as_deref() == Some(value.as_str()));
        assert!(found, "{:?}={:?} not found in {}", key, value, built);
    }
});
