use std::io::{self, Read};

use ecgfp5::curve::Point;
use ecgfp5::field::GFp5;
use ecgfp5::scalar::Scalar;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
enum Command {
    HashEncKey { pk_hex: String },
    DerivePubkey { sk_hex: String },
    ReencryptBallot { pk_hex: String, k_hex: String, ballot: BallotJson },
    AddBallots { ballots: Vec<BallotJson> },
    SubBallots { base: BallotJson, subtract: Vec<BallotJson> },
    LeafHash { ballot: BallotJson },
    DecryptTotals { sk_hex: String, ballot: BallotJson, max_total: u64 },
}

#[derive(Serialize, Deserialize, Clone)]
struct CipherJson {
    c1: String,
    c2: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct BallotJson {
    fields: Vec<CipherJson>,
}

#[derive(Serialize)]
struct OutBallot {
    ballot: BallotJson,
}

#[derive(Serialize)]
struct OutHash {
    hash_hex: String,
}

#[derive(Serialize)]
struct OutPubKey {
    pk_hex: String,
}

#[derive(Serialize)]
struct OutTotals {
    totals: Vec<u64>,
}

fn decode_point(hex_str: &str) -> Point {
    let bytes = hex::decode(hex_str.trim_start_matches("0x")).unwrap();
    let (w, ok) = GFp5::decode(&bytes);
    assert_eq!(ok, u64::MAX);
    let (p, ok2) = Point::decode(w);
    assert_eq!(ok2, u64::MAX);
    p
}

fn encode_point(p: Point) -> String {
    hex::encode(p.encode().encode())
}

fn decode_scalar(hex_str: &str) -> Scalar {
    let bytes = hex::decode(hex_str.trim_start_matches("0x")).unwrap();
    Scalar::decode_reduce(&bytes)
}

fn hash_enc_key(pk: Point) -> String {
    let digest = Sha256::digest(pk.encode().encode());
    hex::encode(digest)
}

fn ballot_leaf_hash(ballot: &BallotJson) -> String {
    let mut h = Sha256::new();
    for f in &ballot.fields {
        h.update(hex::decode(&f.c1).unwrap());
        h.update(hex::decode(&f.c2).unwrap());
    }
    hex::encode(h.finalize())
}

fn reencrypt_ballot(pk: Point, k_hex: &str, ballot: &BallotJson) -> BallotJson {
    let k_bytes = hex::decode(k_hex.trim_start_matches("0x")).unwrap();
    let k = Scalar::decode_reduce(&k_bytes);
    let delta1 = Point::mulgen(k);
    let delta2 = pk * k;
    let fields = ballot.fields.iter().map(|f| {
        let c1 = decode_point(&f.c1) + delta1;
        let c2 = decode_point(&f.c2) + delta2;
        CipherJson { c1: encode_point(c1), c2: encode_point(c2) }
    }).collect();
    BallotJson { fields }
}

fn add_ballots(ballots: &[BallotJson]) -> BallotJson {
    let mut c1 = [Point::NEUTRAL; 8];
    let mut c2 = [Point::NEUTRAL; 8];
    for ballot in ballots {
        for (i, f) in ballot.fields.iter().enumerate() {
            c1[i] = c1[i] + decode_point(&f.c1);
            c2[i] = c2[i] + decode_point(&f.c2);
        }
    }
    BallotJson { fields: (0..8).map(|i| CipherJson { c1: encode_point(c1[i]), c2: encode_point(c2[i]) }).collect() }
}

fn sub_ballots(base: &BallotJson, subtract: &[BallotJson]) -> BallotJson {
    let mut c1 = [Point::NEUTRAL; 8];
    let mut c2 = [Point::NEUTRAL; 8];
    for (i, f) in base.fields.iter().enumerate() {
        c1[i] = decode_point(&f.c1);
        c2[i] = decode_point(&f.c2);
    }
    for ballot in subtract {
        for (i, f) in ballot.fields.iter().enumerate() {
            c1[i] = c1[i] - decode_point(&f.c1);
            c2[i] = c2[i] - decode_point(&f.c2);
        }
    }
    BallotJson { fields: (0..8).map(|i| CipherJson { c1: encode_point(c1[i]), c2: encode_point(c2[i]) }).collect() }
}

fn decrypt_totals(sk_hex: &str, ballot: &BallotJson, max_total: u64) -> Vec<u64> {
    let sk = decode_scalar(sk_hex);
    let mut table = Vec::with_capacity((max_total + 1) as usize);
    let mut acc = Point::NEUTRAL;
    let generator = Point::GENERATOR;
    table.push(acc.encode().encode());
    for _ in 0..max_total {
        acc = acc + generator;
        table.push(acc.encode().encode());
    }
    ballot.fields.iter().map(|f| {
        let c1 = decode_point(&f.c1);
        let c2 = decode_point(&f.c2);
        let m = c2 - (c1 * sk);
        let enc = m.encode().encode();
        table.iter().position(|candidate| *candidate == enc).map(|i| i as u64).unwrap_or(u64::MAX)
    }).collect()
}

fn main() {
    let mut raw = String::new();
    io::stdin().read_to_string(&mut raw).unwrap();
    let cmd: Command = serde_json::from_str(&raw).unwrap();
    match cmd {
        Command::HashEncKey { pk_hex } => println!("{}", serde_json::to_string(&OutHash { hash_hex: hash_enc_key(decode_point(&pk_hex)) }).unwrap()),
        Command::DerivePubkey { sk_hex } => println!("{}", serde_json::to_string(&OutPubKey { pk_hex: encode_point(Point::mulgen(decode_scalar(&sk_hex))) }).unwrap()),
        Command::ReencryptBallot { pk_hex, k_hex, ballot } => println!("{}", serde_json::to_string(&OutBallot { ballot: reencrypt_ballot(decode_point(&pk_hex), &k_hex, &ballot) }).unwrap()),
        Command::AddBallots { ballots } => println!("{}", serde_json::to_string(&OutBallot { ballot: add_ballots(&ballots) }).unwrap()),
        Command::SubBallots { base, subtract } => println!("{}", serde_json::to_string(&OutBallot { ballot: sub_ballots(&base, &subtract) }).unwrap()),
        Command::LeafHash { ballot } => println!("{}", serde_json::to_string(&OutHash { hash_hex: ballot_leaf_hash(&ballot) }).unwrap()),
        Command::DecryptTotals { sk_hex, ballot, max_total } => println!("{}", serde_json::to_string(&OutTotals { totals: decrypt_totals(&sk_hex, &ballot, max_total) }).unwrap()),
    }
}
