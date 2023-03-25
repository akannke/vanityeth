use bigint::U256;

use clap::Parser;
use libsecp256k1::{PublicKey, SecretKey};
use rand::Rng;
use rayon::iter::ParallelIterator;
use rayon::prelude::IntoParallelIterator;
use sha3::{Digest, Keccak256};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Parser, Debug)]
#[clap(
    name = "vanity-address-generator",
    version = "0.1.0",
    about = "A simple Ethereum vanity address generator"
)]
struct Opt {
    /// Desired vanity prefix (e.g., "1abc")
    #[clap(value_name = "PREFIX")]
    prefix: String,
    /// Number of threads to use for searching
    #[clap(short = 't', long)]
    threads: Option<usize>,
    /// Display search statistics every N seconds
    #[clap(short = 's', long, default_value = "1")]
    stats_interval: u64,
}

fn generate_private_key_from_seed_and_nonce(seed: &SecretKey, nonce: u64) -> SecretKey {
    let seed_value = U256::from_big_endian(&seed.serialize());
    let new_value = seed_value + nonce.into();
    let mut new_secret_key_bytes = [0u8; 32];
    new_value.to_big_endian(&mut new_secret_key_bytes);
    SecretKey::parse(&new_secret_key_bytes).expect("Generated private key is invalid")
}

fn derive_public_key(secret_key: &SecretKey) -> PublicKey {
    PublicKey::from_secret_key(secret_key)
}

fn derive_address(public_key: &PublicKey) -> String {
    let mut hasher = Keccak256::new();
    hasher.update(&public_key.serialize()[1..]);
    let hash = hasher.finalize();
    let address_bytes = &hash[12..];
    hex::encode(&address_bytes)
}

fn generate_random_private_key(rng: &mut impl Rng) -> SecretKey {
    loop {
        let mut secret_key = [0u8; 32];
        rng.fill_bytes(&mut secret_key);

        if let Ok(secret_key) = SecretKey::parse(&secret_key) {
            return secret_key;
        }
    }
}

fn main() {
    let opt = Opt::parse();
    let default_threads = num_cpus::get();
    let threads = opt.threads.unwrap_or(default_threads);
    let prefix = opt.prefix.trim_start_matches("0x").to_owned();

    let found = Arc::new(AtomicBool::new(false));

    let searched_addresses = Arc::new(AtomicU64::new(0));
    let start_time = Instant::now();

    let _stats_thread = {
        let searched_addresses = Arc::clone(&searched_addresses);
        let found = Arc::clone(&found);
        let prefix = prefix.clone();

        thread::spawn(move || {
            while !found.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_secs(opt.stats_interval));

                let total_searched = searched_addresses.load(Ordering::SeqCst);
                let rate = total_searched as f64 / start_time.elapsed().as_secs_f64();
                let probability = total_searched as f64 / (16u64.pow(prefix.len() as u32) as f64);

                println!(
                    "Total searched addresses: {}, Rate: {} addresses/sec, Probability: {:.4}",
                    total_searched, rate, probability
                );
            }
        })
    };

    let _: Vec<()> = (0..threads)
        .into_par_iter()
        .map_init(
            || (rand::thread_rng()),
            |mut rng, _| {
                let mut nonce = 0;
                let seed = generate_random_private_key(&mut rng);

                while !found.load(Ordering::SeqCst) {
                    let private_key = generate_private_key_from_seed_and_nonce(&seed, nonce);
                    let public_key = derive_public_key(&private_key);
                    let address = derive_address(&public_key);

                    searched_addresses.fetch_add(1, Ordering::SeqCst);

                    if address.starts_with(&prefix) {
                        found.store(true, Ordering::SeqCst);
                        println!("Address: 0x{}", address);
                        println!("Private Key: {}", hex::encode(&private_key.serialize()));
                        break;
                    }

                    nonce += 1;
                }
            },
        )
        .collect();
}
