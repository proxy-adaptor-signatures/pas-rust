//! Comprehensive integration tests for cryptographic operations.
//!
//! These tests verify the correctness of the complete protocol flow
//! and ensure that all cryptographic operations compose correctly.

#[cfg(test)]
mod tests {
    use crate::exn;
    use crate::{
        algo::{
            ad_gen, ad_verify,
            curves::Secp256k1Curve as C,
            party_i::{BlindedWitness, Share},
            pve_combine, pve_decrypt, pve_encrypt_link_secp,
            pve_paillier::{load_pzk_aux, load_security_params},
            threshold_ops::{reconstruct_secret, validate_shares},
            ThresholdCurve,
        },
        pve_decrypt_integer,
    };
    use rand_core::OsRng;
    use rug::Integer;
    use xuanmi_base_support::{Outcome, *};

    fn load_paillier_sk() -> Outcome<fast_paillier::DecryptionKey> {
        let s = include_str!("../../assets/paillier_keystore.json");
        serde_json::from_str(&s).catch(exn::JsonToObjectException, "")
    }

    /// Test that AdGen/AdVerify work correctly
    #[test]
    fn test_advertisement_generation_verification() {
        let mut rng = OsRng;
        let witness = C::random_scalar(&mut rng);
        let statement = C::mul_base(&witness);
        let sk = &load_paillier_sk().unwrap();

        // Generate advertisement
        let ad_output = ad_gen::<C, _>(&statement, &witness, &sk, &mut rng).unwrap();

        // Verify advertisement
        assert_eq!(ad_verify::<C>(&statement, &ad_output.advt).unwrap(), true);

        // Verify with wrong statement should fail
        let wrong_statement = C::mul_base(&C::random_scalar(&mut rng));
        let wrong_result = ad_verify::<C>(&wrong_statement, &ad_output.advt);
        assert_eq!(wrong_result.unwrap(), false);
    }

    /// Test PVE encrypt/decrypt roundtrip
    #[test]
    fn test_pve_encrypt_decrypt_roundtrip() {
        // This test requires PZK parameters - skip if not available
        let aux = match load_pzk_aux() {
            Ok(a) => a,
            Err(_) => return, // Skip test if assets not available
        };
        let security = match load_security_params() {
            Ok(s) => s,
            Err(_) => return,
        };

        println!("PZK parameters loaded successfully");

        let mut rng = OsRng;

        // Generate Paillier keypair
        let sk = &load_paillier_sk().unwrap();
        let pk = &sk.encryption_key();

        // Test data
        let plaintext = C::scalar_to_bytes(&C::random_scalar(&mut rng));

        // Encrypt
        let ciphertext = pve_encrypt_link_secp(&aux, &security, pk, &plaintext).unwrap();

        // Decrypt
        let decrypted = pve_decrypt(sk, &ciphertext).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    /// Test threshold secret reconstruction with various share combinations
    #[test]
    fn test_threshold_reconstruction_robustness() {
        // Test 2-of-3 threshold sharing
        let secret = <C as ThresholdCurve>::Scalar::from(12345u64);

        // Create shares for polynomial f(x) = secret + coeff1*x
        let coeff1 = <C as ThresholdCurve>::Scalar::from(67890u64);
        let share1_val = secret + (coeff1 * <C as ThresholdCurve>::Scalar::from(1u64)); // f(1)
        let share2_val = secret + (coeff1 * <C as ThresholdCurve>::Scalar::from(2u64)); // f(2)
        let share3_val = secret + (coeff1 * <C as ThresholdCurve>::Scalar::from(3u64)); // f(3)

        let all_shares = vec![
            Share::new_from(0, 1, share1_val),
            Share::new_from(0, 2, share2_val),
            Share::new_from(0, 3, share3_val),
        ];

        // Test all 2-of-3 combinations
        let combinations = vec![
            vec![all_shares[0].clone(), all_shares[1].clone()],
            vec![all_shares[0].clone(), all_shares[2].clone()],
            vec![all_shares[1].clone(), all_shares[2].clone()],
        ];

        for shares in combinations {
            let reconstructed = reconstruct_secret::<C>(&shares, 0).unwrap();
            assert_eq!(
                reconstructed, secret,
                "Failed to reconstruct secret from shares"
            );
        }

        // Test with all 3 shares (should also work)
        let reconstructed = reconstruct_secret::<C>(&all_shares, 0).unwrap();
        assert_eq!(reconstructed, secret);
    }

    /// Test that blinded witness extraction and unblinding works correctly
    #[test]
    fn test_blinded_witness_extraction_unblinding() {
        let original_witness = <C as ThresholdCurve>::Scalar::from(42u64);

        // Simulate blinding factor shares (2-of-3)
        let r = <C as ThresholdCurve>::Scalar::from(123u64); // Total blinding factor
        let r_coeff = <C as ThresholdCurve>::Scalar::from(456u64);
        let r1 = r + (r_coeff * <C as ThresholdCurve>::Scalar::from(1u64)); // r share for party 1
        let r2 = r + (r_coeff * <C as ThresholdCurve>::Scalar::from(2u64)); // r share for party 2
        let r3 = r + (r_coeff * <C as ThresholdCurve>::Scalar::from(3u64)); // r share for party 3

        let r_shares = vec![
            Share::new_from(0, 1, r1),
            Share::new_from(0, 2, r2),
            Share::new_from(0, 3, r3),
        ];

        // Create blinded witness
        let blinded_witness_value = original_witness + r;
        let blinded_witness = BlindedWitness::<C>(blinded_witness_value);

        // Test unblinding with 2-of-3 shares
        let subset_shares = vec![r_shares[0].clone(), r_shares[1].clone()];
        let unblinded = blinded_witness
            .unblind(&subset_shares, &vec![1, 2, 3])
            .unwrap();

        assert_eq!(
            unblinded, original_witness,
            "Unblinded witness should match original"
        );

        // Test with different 2-of-3 combination
        let subset_shares2 = vec![r_shares[1].clone(), r_shares[2].clone()];
        let unblinded2 = blinded_witness
            .unblind(&subset_shares2, &vec![1, 2, 3])
            .unwrap();

        assert_eq!(
            unblinded2, original_witness,
            "Different share combination should give same result"
        );
    }

    /// Test PVE homomorphic combination properties
    #[test]
    fn test_pve_homomorphic_combination() {
        // Skip if PZK parameters not available
        let aux = match load_pzk_aux() {
            Ok(a) => a,
            Err(_) => return,
        };
        let security = match load_security_params() {
            Ok(s) => s,
            Err(_) => return,
        };

        println!("PZK parameters loaded successfully");

        let sk = &load_paillier_sk().unwrap();
        let pk = &sk.encryption_key();

        // Create two plaintexts
        let val1 = <C as ThresholdCurve>::Scalar::from(100u64);
        let val2 = <C as ThresholdCurve>::Scalar::from(200u64);
        let scalar1 = <C as ThresholdCurve>::Scalar::from(3u64);
        let scalar2 = <C as ThresholdCurve>::Scalar::from(5u64);
        let sum_expected = val1 * scalar1 + val2 * scalar2;

        let pt1 = C::scalar_to_bytes(&val1);
        let pt2 = C::scalar_to_bytes(&val2);
        let scalar1_bytes = C::scalar_to_bytes(&scalar1);
        let scalar2_bytes = C::scalar_to_bytes(&scalar2);

        // Encrypt both
        let ct1 = pve_encrypt_link_secp(&aux, &security, pk, &pt1).unwrap();
        let ct2 = pve_encrypt_link_secp(&aux, &security, pk, &pt2).unwrap();

        let pairs = vec![
            (
                ct1,
                Integer::from_digits(&scalar1_bytes, rug::integer::Order::MsfBe),
            ),
            (
                ct2,
                Integer::from_digits(&scalar2_bytes, rug::integer::Order::MsfBe),
            ),
        ];

        let combined = pve_combine(pk, &pairs, 32).unwrap();
        let decrypted_combined = pve_decrypt_integer(sk, &combined).unwrap();
        let decrypted_bytes = crate::integer_mod_secp_to_32be(&decrypted_combined);

        let mut expected_bytes = [0u8; 32];
        expected_bytes.copy_from_slice(&C::scalar_to_bytes(&sum_expected));

        // Note: Paillier arithmetic is modular, so we need to handle potential overflow
        let reconstructed_scalar = C::scalar_from_bytes_reduced(decrypted_bytes);

        // The homomorphic property should hold: Enc(a) * Enc(b) = Enc(a + b)
        assert_eq!(
            reconstructed_scalar, sum_expected,
            "Homomorphic combination failed"
        );
    }

    /// Test share validation catches common errors
    #[test]
    fn test_share_validation_errors() {
        // Empty shares
        let empty_shares: Vec<Share<C>> = vec![];
        assert!(validate_shares::<C>(&empty_shares, 1).is_err());

        // Insufficient shares
        let insufficient = vec![Share::new_from(
            0,
            1,
            <C as ThresholdCurve>::Scalar::from(1u64),
        )];
        assert!(validate_shares::<C>(&insufficient, 2).is_err());

        // Duplicate indices
        let duplicates = vec![
            Share::new_from(0, 1, <C as ThresholdCurve>::Scalar::from(1u64)),
            Share::new_from(0, 1, <C as ThresholdCurve>::Scalar::from(2u64)),
        ];
        assert!(validate_shares::<C>(&duplicates, 2).is_err());

        // Zero index (reserved)
        let zero_index = vec![
            Share::new_from(0, 0, <C as ThresholdCurve>::Scalar::from(1u64)),
            Share::new_from(0, 1, <C as ThresholdCurve>::Scalar::from(2u64)),
        ];
        assert!(validate_shares::<C>(&zero_index, 2).is_err());

        // Valid shares should pass
        let valid = vec![
            Share::new_from(0, 1, <C as ThresholdCurve>::Scalar::from(1u64)),
            Share::new_from(0, 2, <C as ThresholdCurve>::Scalar::from(2u64)),
        ];
        assert!(validate_shares::<C>(&valid, 2).is_ok());
    }
}
