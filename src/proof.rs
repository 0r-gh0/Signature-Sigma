use ark_bls12_381::{Fr, G1Affine};
use zeroize::Zeroize;

pub struct Proof {
    pub a_prime:  G1Affine,   // r1·A
    pub a_bar:    G1Affine,   // r1·B - e·A_prime  (= x·A_prime)
    pub d:        G1Affine,   // r1·B - r2·h0
    pub cap_r:    G1Affine,   // Pedersen blinding commitment R (the G1 point)
    pub t1:       G1Affine,
    pub t2:       G1Affine,
    pub z_m:      Fr,
    pub z_r:      Fr,
    pub z_e:      Fr,
    pub z_r2:     Fr,
    pub z_r3:     Fr,
    pub z_sprime: Fr,
}

/// Sensitive prover state. Zeroized on drop. Never returned to caller.
#[allow(dead_code)]
pub(crate) struct ProverSecrets {
    pub r1:          Fr,
    pub r2:          Fr,
    pub r3:          Fr,       // = r1⁻¹
    pub s_prime:     Fr,       // = s - r2·r3
    pub temp_m:      Fr,
    pub temp_r:      Fr,
    pub temp_e:      Fr,
    pub temp_r2:     Fr,
    pub temp_r3:     Fr,
    pub temp_sprime: Fr,
}

impl Zeroize for ProverSecrets {
    fn zeroize(&mut self) {
        // Fr doesn't implement Zeroize; zero raw memory with volatile writes
        // to prevent the optimizer from eliding them.
        let ptr = self as *mut ProverSecrets as *mut u8;
        let len = std::mem::size_of::<ProverSecrets>();
        for i in 0..len {
            // SAFETY: ptr is valid, in-bounds, and properly aligned as *mut u8
            unsafe { std::ptr::write_volatile(ptr.add(i), 0u8); }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

impl Drop for ProverSecrets {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_ec::AffineRepr;
    use ark_ff::{UniformRand, Zero};
    use zeroize::Zeroize;

    #[test]
    fn test_proof_fields_accessible() {
        let zero_g1 = G1Affine::zero();
        let p = Proof {
            a_prime: zero_g1,
            a_bar: zero_g1,
            d: zero_g1,
            cap_r: zero_g1,
            t1: zero_g1,
            t2: zero_g1,
            z_m: Fr::zero(),
            z_r: Fr::zero(),
            z_e: Fr::zero(),
            z_r2: Fr::zero(),
            z_r3: Fr::zero(),
            z_sprime: Fr::zero(),
        };
        assert_eq!(p.z_m, Fr::zero());
    }

    #[test]
    fn test_prover_secrets_zeroize() {
        let mut s = ProverSecrets {
            r1:          Fr::rand(&mut ark_std::test_rng()),
            r2:          Fr::rand(&mut ark_std::test_rng()),
            r3:          Fr::rand(&mut ark_std::test_rng()),
            s_prime:     Fr::rand(&mut ark_std::test_rng()),
            temp_m:      Fr::rand(&mut ark_std::test_rng()),
            temp_r:      Fr::rand(&mut ark_std::test_rng()),
            temp_e:      Fr::rand(&mut ark_std::test_rng()),
            temp_r2:     Fr::rand(&mut ark_std::test_rng()),
            temp_r3:     Fr::rand(&mut ark_std::test_rng()),
            temp_sprime: Fr::rand(&mut ark_std::test_rng()),
        };
        s.zeroize();
        assert_eq!(s.r1, Fr::zero());
        assert_eq!(s.r2, Fr::zero());
    }
}
