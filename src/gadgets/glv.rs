use std::marker::PhantomData;

use plonky2::hash::hash_types::RichField;
use plonky2::iop::generator::{GeneratedValues, SimpleGenerator};
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::PartitionWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2_field::extension_field::Extendable;
use plonky2_field::field_types::{Field, PrimeField};

use crate::curve::ed25519::Ed25519;
use crate::curve::glv::{decompose_ed25519_scalar, GLV_BETA, GLV_S};
use crate::field::ed25519_base::Ed25519Base;
use crate::field::ed25519_scalar::Ed25519Scalar;
use crate::gadgets::biguint::{buffer_set_biguint_target, witness_get_biguint_target};
use crate::gadgets::curve::{AffinePointTarget, CircuitBuilderCurve};
use crate::gadgets::curve_msm::curve_msm_circuit;
use crate::gadgets::nonnative::{CircuitBuilderNonNative, NonNativeTarget};

pub trait CircuitBuilderGlv<F: RichField + Extendable<D>, const D: usize> {
    fn ed25519_glv_beta(&mut self) -> NonNativeTarget<Ed25519Base>;

    fn decompose_ed25519_scalar(
        &mut self,
        k: &NonNativeTarget<Ed25519Scalar>,
    ) -> (
        NonNativeTarget<Ed25519Scalar>,
        NonNativeTarget<Ed25519Scalar>,
        BoolTarget,
        BoolTarget,
    );

    fn glv_mul(
        &mut self,
        p: &AffinePointTarget<Ed25519>,
        k: &NonNativeTarget<Ed25519Scalar>,
    ) -> AffinePointTarget<Ed25519>;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderGlv<F, D>
    for CircuitBuilder<F, D>
{
    fn ed25519_glv_beta(&mut self) -> NonNativeTarget<Ed25519Base> {
        self.constant_nonnative(GLV_BETA)
    }

    fn decompose_ed25519_scalar(
        &mut self,
        k: &NonNativeTarget<Ed25519Scalar>,
    ) -> (
        NonNativeTarget<Ed25519Scalar>,
        NonNativeTarget<Ed25519Scalar>,
        BoolTarget,
        BoolTarget,
    ) {
        let k1 = self.add_virtual_nonnative_target_sized::<Ed25519Scalar>(4);
        let k2 = self.add_virtual_nonnative_target_sized::<Ed25519Scalar>(4);
        let k1_neg = self.add_virtual_bool_target();
        let k2_neg = self.add_virtual_bool_target();

        self.add_simple_generator(GLVDecompositionGenerator::<F, D> {
            k: k.clone(),
            k1: k1.clone(),
            k2: k2.clone(),
            k1_neg,
            k2_neg,
            _phantom: PhantomData,
        });

        // Check that `k1_raw + GLV_S * k2_raw == k`.
        let k1_raw = self.nonnative_conditional_neg(&k1, k1_neg);
        let k2_raw = self.nonnative_conditional_neg(&k2, k2_neg);
        let s = self.constant_nonnative(GLV_S);
        let mut should_be_k = self.mul_nonnative(&s, &k2_raw);
        should_be_k = self.add_nonnative(&should_be_k, &k1_raw);
        self.connect_nonnative(&should_be_k, k);

        (k1, k2, k1_neg, k2_neg)
    }

    fn glv_mul(
        &mut self,
        p: &AffinePointTarget<Ed25519>,
        k: &NonNativeTarget<Ed25519Scalar>,
    ) -> AffinePointTarget<Ed25519> {
        let (k1, k2, k1_neg, k2_neg) = self.decompose_ed25519_scalar(k);

        let beta = self.ed25519_glv_beta();
        let beta_px = self.mul_nonnative(&beta, &p.x);
        let sp = AffinePointTarget::<Ed25519> {
            x: beta_px,
            y: p.y.clone(),
        };

        let p_neg = self.curve_conditional_neg(p, k1_neg);
        let sp_neg = self.curve_conditional_neg(&sp, k2_neg);
        curve_msm_circuit(self, &p_neg, &sp_neg, &k1, &k2)
    }
}

#[derive(Debug)]
struct GLVDecompositionGenerator<F: RichField + Extendable<D>, const D: usize> {
    k: NonNativeTarget<Ed25519Scalar>,
    k1: NonNativeTarget<Ed25519Scalar>,
    k2: NonNativeTarget<Ed25519Scalar>,
    k1_neg: BoolTarget,
    k2_neg: BoolTarget,
    _phantom: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize> SimpleGenerator<F>
    for GLVDecompositionGenerator<F, D>
{
    fn dependencies(&self) -> Vec<Target> {
        self.k.value.limbs.iter().map(|l| l.0).collect()
    }

    fn run_once(&self, witness: &PartitionWitness<F>, out_buffer: &mut GeneratedValues<F>) {
        let k =
            Ed25519Scalar::from_biguint(witness_get_biguint_target(witness, self.k.value.clone()));

        let (k1, k2, k1_neg, k2_neg) = decompose_ed25519_scalar(k);

        buffer_set_biguint_target(out_buffer, &self.k1.value, &k1.to_canonical_biguint());
        buffer_set_biguint_target(out_buffer, &self.k2.value, &k2.to_canonical_biguint());
        out_buffer.set_bool_target(self.k1_neg, k1_neg);
        out_buffer.set_bool_target(self.k2_neg, k2_neg);
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2_field::field_types::Field;

    use crate::curve::curve_types::{Curve, CurveScalar};
    use crate::curve::ed25519::Ed25519;
    use crate::curve::glv::glv_mul;
    use crate::field::ed25519_scalar::Ed25519Scalar;
    use crate::gadgets::curve::CircuitBuilderCurve;
    use crate::gadgets::glv::CircuitBuilderGlv;
    use crate::gadgets::nonnative::CircuitBuilderNonNative;

    #[test]
    #[ignore]
    fn test_glv_gadget() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_ecc_config();

        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let rando =
            (CurveScalar(Ed25519Scalar::rand()) * Ed25519::GENERATOR_PROJECTIVE).to_affine();
        let randot = builder.constant_affine_point(rando);

        let scalar = Ed25519Scalar::rand();
        let scalar_target = builder.constant_nonnative(scalar);

        let rando_glv_scalar = glv_mul(rando.to_projective(), scalar);
        let expected = builder.constant_affine_point(rando_glv_scalar.to_affine());
        let actual = builder.glv_mul(&randot, &scalar_target);
        builder.connect_affine_point(&expected, &actual);

        dbg!(builder.num_gates());
        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();

        data.verify(proof)
    }
}
