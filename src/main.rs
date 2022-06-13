#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

use log::{info, Level, LevelFilter};
use anyhow::Result;
use plonky2::gates::noop::NoopGate;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::{PartialWitness, Witness};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, Hasher, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::{CompressedProofWithPublicInputs, ProofWithPublicInputs};
use plonky2::plonk::prover::prove;
use plonky2::util::timing::TimingTree;
use plonky2_ed25519::gadgets::eddsa::verify_message_circuit;
use plonky2_ed25519::gadgets::eddsa::EDDSASignatureTarget;
use plonky2_ed25519::gadgets::curve::CircuitBuilderCurve;
use plonky2_ed25519::gadgets::nonnative::CircuitBuilderNonNative;
use plonky2_ed25519::gadgets::eddsa::EDDSAPublicKeyTarget;
use plonky2_ed25519::curve::eddsa::EDDSASignature;
use plonky2_ed25519::curve::eddsa::{SAMPLE_H1, SAMPLE_H2, SAMPLE_PK1, SAMPLE_SIG1, SAMPLE_SIG2};
use plonky2_ed25519::curve::ed25519::Ed25519;
use plonky2_ed25519::curve::curve_types::AffinePoint;
use plonky2_ed25519::field::ed25519_scalar::Ed25519Scalar;
use plonky2_field::extension_field::Extendable;

type ProofTuple<F, C, const D: usize> = (
    ProofWithPublicInputs<F, C, D>,
    VerifierOnlyCircuitData<C, D>,
    CommonCircuitData<F, C, D>,
);

fn prove_ed25519<F: RichField + Extendable<D>, C: GenericConfig<D, F=F>, const D: usize>(
    h: Ed25519Scalar,
    sig: EDDSASignature<Ed25519>,
    pk: AffinePoint<Ed25519>)
    -> Result<ProofTuple<F, C, D>>
    where
        [(); C::Hasher::HASH_SIZE]:, {
    let pw = PartialWitness::new();
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::wide_ecc_config());

    let msg_target = builder.constant_nonnative(h);
    let pk_target = EDDSAPublicKeyTarget(builder.constant_affine_point(pk));
    let sig_target = EDDSASignatureTarget {
        r: builder.constant_affine_point(sig.r),
        s: builder.constant_nonnative(sig.s),
    };

    verify_message_circuit(&mut builder, msg_target, sig_target, pk_target);

    println!("Constructing inner proof with {} gates", builder.num_gates());
    let data = builder.build::<C>();

    let timing = TimingTree::new("prove", Level::Debug);
    let proof = data.prove(pw).unwrap();
    timing.print();

    let timing = TimingTree::new("verify", Level::Debug);
    data.verify(proof.clone()).expect("verify error");
    timing.print();

    test_serialization(&proof, &data.common)?;
    Ok((proof, data.verifier_only, data.common))
}

fn recursive_proof<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F=F>,
    InnerC: GenericConfig<D, F=F>,
    const D: usize,
>(
    inner1: &ProofTuple<F, InnerC, D>,
    inner2: Option<ProofTuple<F, InnerC, D>>,
    config: &CircuitConfig,
    min_degree_bits: Option<usize>,
) -> Result<ProofTuple<F, C, D>>
    where
        InnerC::Hasher: AlgebraicHasher<F>,
        [(); C::Hasher::HASH_SIZE]:,
{
    let mut builder = CircuitBuilder::<F, D>::new(config.clone());
    let mut pw = PartialWitness::new();

    {
        let (inner_proof, inner_vd, inner_cd) = inner1;
        let pt = builder.add_virtual_proof_with_pis(inner_cd);
        pw.set_proof_with_pis_target(&pt, inner_proof);

        let inner_data = VerifierCircuitTarget {
            constants_sigmas_cap: builder.add_virtual_cap(inner_cd.config.fri_config.cap_height),
        };
        pw.set_cap_target(
            &inner_data.constants_sigmas_cap,
            &inner_vd.constants_sigmas_cap,
        );

        builder.verify_proof(pt, &inner_data, inner_cd);
    }

    if inner2.is_some() {
        let (inner_proof, inner_vd, inner_cd) = inner2.unwrap();
        let pt = builder.add_virtual_proof_with_pis(&inner_cd);
        pw.set_proof_with_pis_target(&pt, &inner_proof);

        let inner_data = VerifierCircuitTarget {
            constants_sigmas_cap: builder.add_virtual_cap(inner_cd.config.fri_config.cap_height),
        };
        pw.set_cap_target(
            &inner_data.constants_sigmas_cap,
            &inner_vd.constants_sigmas_cap,
        );

        builder.verify_proof(pt, &inner_data, &inner_cd);
    }
    builder.print_gate_counts(0);

    if let Some(min_degree_bits) = min_degree_bits {
        // We don't want to pad all the way up to 2^min_degree_bits, as the builder will
        // add a few special gates afterward. So just pad to 2^(min_degree_bits
        // - 1) + 1. Then the builder will pad to the next power of two,
        // 2^min_degree_bits.
        let min_gates = (1 << (min_degree_bits - 1)) + 1;
        for _ in builder.num_gates()..min_gates {
            builder.add_gate(NoopGate, vec![]);
        }
    }

    let data = builder.build::<C>();

    let mut timing = TimingTree::new("prove", Level::Debug);
    let proof = prove(&data.prover_only, &data.common, pw, &mut timing)?;
    timing.print();

    data.verify(proof.clone())?;

    test_serialization(&proof, &data.common)?;
    Ok((proof, data.verifier_only, data.common))
}

fn benchmark() -> Result<()> {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    let config = CircuitConfig::standard_recursion_config();

    let proof1 = prove_ed25519(SAMPLE_H1, SAMPLE_SIG1, SAMPLE_PK1).expect("prove error 1");
    let proof2 = prove_ed25519(SAMPLE_H2, SAMPLE_SIG2, SAMPLE_PK1).expect("prove error 2");

    // Recursively verify the proof
    let middle = recursive_proof::<F, C, C, D>(&proof1, Some(proof2), &config, None)?;
    let (_, _, cd) = &middle;
    info!(
        "Single recursion proof degree {} = 2^{}",
        cd.degree(),
        cd.degree_bits
    );

    // Add a second layer of recursion to shrink the proof size further
    let outer = recursive_proof::<F, C, C, D>(&middle, None, &config, None)?;
    let (_, _, cd) = &outer;
    info!(
        "Double recursion proof degree {} = 2^{}",
        cd.degree(),
        cd.degree_bits
    );

    Ok(())
}

/// Test serialization and print some size info.
fn test_serialization<F: RichField + Extendable<D>, C: GenericConfig<D, F=F>, const D: usize>(
    proof: &ProofWithPublicInputs<F, C, D>,
    cd: &CommonCircuitData<F, C, D>,
) -> Result<()>
    where
        [(); C::Hasher::HASH_SIZE]:,
{
    let proof_bytes = proof.to_bytes()?;
    info!("Proof length: {} bytes", proof_bytes.len());
    let proof_from_bytes = ProofWithPublicInputs::from_bytes(proof_bytes, cd)?;
    assert_eq!(proof, &proof_from_bytes);

    let now = std::time::Instant::now();
    let compressed_proof = proof.clone().compress(cd)?;
    let decompressed_compressed_proof = compressed_proof.clone().decompress(cd)?;
    info!("{:.4}s to compress proof", now.elapsed().as_secs_f64());
    assert_eq!(proof, &decompressed_compressed_proof);

    let compressed_proof_bytes = compressed_proof.to_bytes()?;
    info!(
        "Compressed proof length: {} bytes",
        compressed_proof_bytes.len()
    );
    let compressed_proof_from_bytes =
        CompressedProofWithPublicInputs::from_bytes(compressed_proof_bytes, cd)?;
    assert_eq!(compressed_proof, compressed_proof_from_bytes);

    Ok(())
}

fn main() -> Result<()> {
    // Initialize logging
    let mut builder = env_logger::Builder::from_default_env();
    builder.format_timestamp(None);
    builder.filter_level(LevelFilter::Debug);
    builder.try_init()?;

    // Run the benchmark
    benchmark()
}
