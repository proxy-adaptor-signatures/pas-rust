//! Safe, tested threshold cryptographic operations.
//!
//! This module provides well-tested primitives for threshold operations
//! with clear invariants and comprehensive unit tests.

use crate::algo::party_i::Share;
use crate::algo::threshold_sig::{ThresholdCurve, ThresholdSig};
use crate::exn;
use xuanmi_base_support::*;

/// Securely reconstruct a secret from threshold shares using Lagrange interpolation.
///
/// # Arguments
/// * `shares` - The threshold shares (must have at least t+1 shares)
/// * `eval_point` - The x-coordinate to evaluate at (typically 0 for secret reconstruction)
///
/// # Returns
/// The reconstructed secret value
///
/// # Security Notes
/// - Uses only the provided shares for Lagrange coefficient calculation
/// - Validates that shares have unique indices to prevent attacks
/// - Requires at least 2 shares (single share reconstruction is trivial but suspicious)
pub fn reconstruct_secret<C: ThresholdCurve>(
    shares: &[Share<C>],
    eval_point: u16,
) -> Outcome<C::Scalar> {
    if shares.is_empty() {
        throw!(name = exn::ConfigException, ctx = "no shares provided");
    }
    if shares.len() == 1 {
        throw!(
            name = exn::ConfigException,
            ctx = "single share reconstruction not allowed"
        );
    }

    // Extract indices and validate uniqueness
    let indices: Vec<u16> = shares.iter().map(|s| s.receiver_index).collect();
    let mut sorted_indices = indices.clone();
    sorted_indices.sort();
    sorted_indices.dedup();
    if sorted_indices.len() != indices.len() {
        throw!(
            name = exn::ConfigException,
            ctx = "duplicate share indices detected"
        );
    }

    // Perform Lagrange interpolation
    let mut result = C::scalar_zero();
    for share in shares {
        let lambda_i =
            ThresholdSig::<C>::get_lagrange_coeff(eval_point, share.receiver_index, &indices)?;
        result = result + (share.get_value() * lambda_i);
    }

    Ok(result)
}

/// Validate that a set of shares is well-formed for threshold operations.
///
/// # Arguments
/// * `shares` - The shares to validate
/// * `min_threshold` - Minimum number of shares required
///
/// # Returns
/// Ok(()) if valid, error otherwise
pub fn validate_shares<C: ThresholdCurve>(
    shares: &[Share<C>],
    min_threshold: usize,
) -> Outcome<()> {
    if shares.len() < min_threshold {
        throw!(
            name = exn::ConfigException,
            ctx = &format!(
                "insufficient shares: got {}, need {}",
                shares.len(),
                min_threshold
            )
        );
    }

    // Check for duplicate indices
    let indices: Vec<u16> = shares.iter().map(|s| s.receiver_index).collect();
    let mut sorted_indices = indices.clone();
    sorted_indices.sort();
    sorted_indices.dedup();
    if sorted_indices.len() != indices.len() {
        throw!(name = exn::ConfigException, ctx = "duplicate share indices");
    }

    // Validate indices are non-zero (0 is reserved for evaluation point)
    for &idx in &indices {
        if idx == 0 {
            throw!(
                name = exn::ConfigException,
                ctx = "share index 0 is reserved"
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algo::curves::Secp256k1Curve as TestCurve;
    #[test]
    fn test_reconstruct_secret_basic() {
        // Create a simple 2-of-3 sharing: secret = 42
        let secret = <TestCurve as ThresholdCurve>::Scalar::from(42u64);

        // Manually create shares for a simple polynomial: f(x) = 42 + 0*x
        // So f(1) = 42, f(2) = 42, f(3) = 42 (constant polynomial)
        let shares = vec![Share::new_from(0, 1, secret), Share::new_from(0, 2, secret)];

        let reconstructed = reconstruct_secret::<TestCurve>(&shares, 0).unwrap();
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_reconstruct_secret_linear() {
        // Create a linear polynomial: f(x) = 10 + 5*x
        // So f(0) = 10 (secret), f(1) = 15, f(2) = 20
        let secret = <TestCurve as ThresholdCurve>::Scalar::from(10u64);
        let share1_val = <TestCurve as ThresholdCurve>::Scalar::from(15u64); // f(1)
        let share2_val = <TestCurve as ThresholdCurve>::Scalar::from(20u64); // f(2)

        let shares = vec![
            Share::new_from(0, 1, share1_val),
            Share::new_from(0, 2, share2_val),
        ];

        let reconstructed = reconstruct_secret::<TestCurve>(&shares, 0).unwrap();
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_validate_shares_success() {
        let shares = vec![
            Share::new_from(0, 1, <TestCurve as ThresholdCurve>::Scalar::from(1u64)),
            Share::new_from(0, 2, <TestCurve as ThresholdCurve>::Scalar::from(2u64)),
        ];

        validate_shares::<TestCurve>(&shares, 2).unwrap();
    }

    #[test]
    fn test_validate_shares_insufficient() {
        let shares = vec![Share::new_from(
            0,
            1,
            <TestCurve as ThresholdCurve>::Scalar::from(1u64),
        )];

        let result = validate_shares::<TestCurve>(&shares, 2);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_shares_duplicate_indices() {
        let shares = vec![
            Share::new_from(0, 1, <TestCurve as ThresholdCurve>::Scalar::from(1u64)),
            Share::new_from(0, 1, <TestCurve as ThresholdCurve>::Scalar::from(2u64)), // duplicate index
        ];

        let result = validate_shares::<TestCurve>(&shares, 2);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_shares_zero_index() {
        let shares = vec![
            Share::new_from(0, 0, <TestCurve as ThresholdCurve>::Scalar::from(1u64)), // invalid index 0
            Share::new_from(0, 1, <TestCurve as ThresholdCurve>::Scalar::from(2u64)),
        ];

        let result = validate_shares::<TestCurve>(&shares, 2);
        assert!(result.is_err());
    }

    #[test]
    fn test_reconstruct_empty_shares() {
        let shares: Vec<Share<TestCurve>> = vec![];
        let result = reconstruct_secret::<TestCurve>(&shares, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_reconstruct_single_share() {
        let shares = vec![Share::new_from(
            0,
            1,
            <TestCurve as ThresholdCurve>::Scalar::from(42u64),
        )];
        let result = reconstruct_secret::<TestCurve>(&shares, 0);
        assert!(result.is_err());
    }
}
