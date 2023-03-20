#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

use anyhow::Result;
use clap::Parser;
use core::num::ParseIntError;
use log::{Level, LevelFilter};
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::{PartialWitness};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{
    CircuitConfig
};
use plonky2::plonk::config::{GenericConfig, Hasher, PoseidonGoldilocksConfig};
use plonky2::util::timing::TimingTree;
use plonky2_ed25519::curve::eddsa::{
    SAMPLE_MSG1, SAMPLE_PK1, SAMPLE_SIG1,
};
use plonky2_ed25519::gadgets::eddsa::{fill_circuits, make_verify_circuits};
use plonky2_field::extension::Extendable;
use std::path::PathBuf;

#[derive(Parser)]
struct Cli {
    #[arg(short, long, default_value_t = 0)]
    benchmark: u8,
    #[arg(short, long, default_value = "./ed25519.proof")]
    output_path: PathBuf,
    #[arg(short, long)]
    msg: Option<String>,
    #[arg(short, long)]
    pk: Option<String>,
    #[arg(short, long)]
    sig: Option<String>,
}

pub fn decode_hex(s: &String) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

fn benchmark_multiple() -> Result<()> {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    prove_ed25519_multiple::<F, C, D>(
        SAMPLE_MSG1.as_bytes(),
        SAMPLE_SIG1.as_slice(),
        SAMPLE_PK1.as_slice(),
    )
    .expect("prove error 1");

    Ok(())
}

fn prove_ed25519_multiple<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    msg: &[u8],
    sigv: &[u8],
    pkv: &[u8],
) -> Result<()>
where
    [(); C::Hasher::HASH_SIZE]:,
{
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::wide_ecc_config());
    let mut pw = PartialWitness::new();
    let repeat_times = 8;
    for _ in 0..repeat_times {
        let targets = make_verify_circuits(&mut builder, msg.len());
        fill_circuits::<F, D>(&mut pw, msg, sigv, pkv, &targets);    
    }

    println!(
        "Constructing inner proof with {} gates",
        builder.num_gates()
    );
    let data = builder.build::<C>();

    let timing = TimingTree::new("prove", Level::Info);
    let proof = data.prove(pw).unwrap();
    timing.print();

    let timing = TimingTree::new("verify", Level::Info);
    data.verify(proof.clone()).expect("verify error");
    timing.print();

    println!("proof size {}", proof.to_bytes().len());

    Ok(())
}


fn main() -> Result<()> {
    // Initialize logging
    let mut builder = env_logger::Builder::from_default_env();
    builder.format_timestamp(None);
    builder.filter_level(LevelFilter::Info);
    builder.try_init()?;

    benchmark_multiple()
}
