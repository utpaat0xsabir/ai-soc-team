#![forbid(unsafe_code)]

use curve25519_dalek::{
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::IsIdentity,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationError {
    PublicKeyLength,
    PublicKeyEncoding,
    PublicKeyNonCanonical,
    PublicKeyNotPrimeOrder,
    PublicKeyIdentity,
    SignatureLength,
    SignatureREncoding,
    SignatureRNonCanonical,
    SignatureRNotPrimeOrder,
    SignatureScalarLength,
    SignatureScalarNonCanonical,
    BackendKeyRejected,
    BackendKeyChanged,
    BackendSignatureChanged,
    SignatureEquationMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PointError {
    Length,
    Encoding,
    NonCanonical,
    NotPrimeOrder,
}

fn decode_prime_order_point(bytes: &[u8]) -> Result<EdwardsPoint, PointError> {
    let encoded: [u8; 32] = bytes.try_into().map_err(|_| PointError::Length)?;
    let point = CompressedEdwardsY(encoded)
        .decompress()
        .ok_or(PointError::Encoding)?;
    if point.compress().to_bytes() != encoded {
        return Err(PointError::NonCanonical);
    }
    if !point.is_torsion_free() {
        return Err(PointError::NotPrimeOrder);
    }
    Ok(point)
}

fn validate_public_key(bytes: &[u8]) -> Result<(), VerificationError> {
    let point = decode_prime_order_point(bytes).map_err(|error| match error {
        PointError::Length => VerificationError::PublicKeyLength,
        PointError::Encoding => VerificationError::PublicKeyEncoding,
        PointError::NonCanonical => VerificationError::PublicKeyNonCanonical,
        PointError::NotPrimeOrder => VerificationError::PublicKeyNotPrimeOrder,
    })?;
    if point.is_identity() {
        return Err(VerificationError::PublicKeyIdentity);
    }
    Ok(())
}

fn validate_signature_r(bytes: &[u8]) -> Result<(), VerificationError> {
    decode_prime_order_point(bytes).map(|_| ()).map_err(|error| match error {
        PointError::Length => VerificationError::SignatureLength,
        PointError::Encoding => VerificationError::SignatureREncoding,
        PointError::NonCanonical => VerificationError::SignatureRNonCanonical,
        PointError::NotPrimeOrder => VerificationError::SignatureRNotPrimeOrder,
    })
}

fn validate_signature_s(bytes: &[u8]) -> Result<(), VerificationError> {
    let encoded: [u8; 32] = bytes
        .try_into()
        .map_err(|_| VerificationError::SignatureScalarLength)?;
    Option::<Scalar>::from(Scalar::from_canonical_bytes(encoded))
        .map(|_| ())
        .ok_or(VerificationError::SignatureScalarNonCanonical)
}

/// TEST-only single-signature Ed25519 validation. This proves no identity, quorum,
/// root-policy, tenant, deployment, or operational authorization.
pub fn verify_hcomp1(
    public_key: &[u8],
    signature: &[u8],
    message: &[u8],
) -> Result<(), VerificationError> {
    validate_public_key(public_key)?;
    if signature.len() != 64 {
        return Err(VerificationError::SignatureLength);
    }

    let (r_bytes, s_bytes) = signature.split_at(32);
    validate_signature_r(r_bytes)?;
    validate_signature_s(s_bytes)?;

    let public_key_bytes: &[u8; 32] = public_key
        .try_into()
        .map_err(|_| VerificationError::PublicKeyLength)?;
    let signature_bytes: &[u8; 64] = signature
        .try_into()
        .map_err(|_| VerificationError::SignatureLength)?;

    let key = VerifyingKey::from_bytes(public_key_bytes)
        .map_err(|_| VerificationError::BackendKeyRejected)?;
    if key.as_bytes() != public_key_bytes {
        return Err(VerificationError::BackendKeyChanged);
    }
    let parsed_signature = Signature::from_bytes(signature_bytes);
    if parsed_signature.to_bytes() != *signature_bytes {
        return Err(VerificationError::BackendSignatureChanged);
    }

    key.verify(message, &parsed_signature)
        .map_err(|_| VerificationError::SignatureEquationMismatch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    const RFC: &str = include_str!("../tests/rfc8032.tsv");
    const WYCHEPROOF: &str = include_str!("../tests/wycheproof.tsv");
    const IDENTITY_R_POSITIVE: &str = include_str!("../tests/identity-r-positive.tsv");
    const IDENTITY: [u8; 32] = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    #[derive(Debug, Eq, PartialEq)]
    enum WycheproofIdError {
        Malformed,
        Duplicate(u32),
        Missing(u32),
        Unexpected(u32),
    }

    fn validate_wycheproof_ids<'a>(ids: impl IntoIterator<Item = &'a str>) -> Result<(), WycheproofIdError> {
        let mut seen = BTreeSet::new();
        for raw_id in ids {
            let id = raw_id.parse::<u32>().map_err(|_| WycheproofIdError::Malformed)?;
            if id.to_string() != raw_id {
                return Err(WycheproofIdError::Malformed);
            }
            if !(1..=210).contains(&id) {
                return Err(WycheproofIdError::Unexpected(id));
            }
            if !seen.insert(id) {
                return Err(WycheproofIdError::Duplicate(id));
            }
        }

        let expected: BTreeSet<u32> = (1..=210).collect();
        if let Some(id) = expected.difference(&seen).next() {
            return Err(WycheproofIdError::Missing(*id));
        }
        if let Some(id) = seen.difference(&expected).next() {
            return Err(WycheproofIdError::Unexpected(*id));
        }
        Ok(())
    }

    fn expected_wycheproof_ids() -> Vec<String> {
        (1..=210).map(|id| id.to_string()).collect()
    }

    fn from_hex(text: &str) -> Vec<u8> {
        if text == "-" {
            return Vec::new();
        }
        assert_eq!(text.len() % 2, 0);
        text.as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let digit = |value: u8| match value {
                    b'0'..=b'9' => value - b'0',
                    b'a'..=b'f' => value - b'a' + 10,
                    _ => panic!("fixture hex must be lowercase ASCII"),
                };
                digit(pair[0]) * 16 + digit(pair[1])
            })
            .collect()
    }

    fn rfc_records() -> Vec<(String, Vec<u8>, Vec<u8>, Vec<u8>)> {
        RFC.lines()
            .filter(|line| !line.is_empty())
            .map(|line| {
                let f: Vec<_> = line.split('\t').collect();
                assert_eq!(f.len(), 6);
                assert_eq!(f[1], "valid");
                assert_eq!(f[2], "ACCEPT");
                (f[0].to_owned(), from_hex(f[3]), from_hex(f[4]), from_hex(f[5]))
            })
            .collect()
    }

    fn wycheproof_record(tc_id: u32) -> Vec<String> {
        WYCHEPROOF
            .lines()
            .filter(|line| !line.is_empty())
            .map(|line| line.split('\t').map(str::to_owned).collect::<Vec<_>>())
            .find(|f| f.first().and_then(|value| value.parse::<u32>().ok()) == Some(tc_id))
            .expect("requested Wycheproof vector exists")
    }

    #[test]
    fn a_validation_positive_and_negative_cases() {
        let (_, public_key, _, _) = rfc_records().remove(0);
        assert_eq!(validate_public_key(&public_key), Ok(()));
        assert_eq!(validate_public_key(&IDENTITY), Err(VerificationError::PublicKeyIdentity));
        assert_eq!(validate_public_key(&[0; 31]), Err(VerificationError::PublicKeyLength));
        assert!(validate_public_key(&[0xff; 32]).is_err());

        let mut noncanonical_identity = IDENTITY;
        noncanonical_identity[31] = 0x80;
        assert!(validate_public_key(&noncanonical_identity).is_err());

        assert_eq!(validate_public_key(&[0; 32]), Err(VerificationError::PublicKeyNotPrimeOrder));
        let mixed_order = from_hex(&wycheproof_record(160)[4]);
        assert_eq!(validate_public_key(&mixed_order), Err(VerificationError::PublicKeyNotPrimeOrder));
    }

    #[test]
    fn r_validation_preserves_identity_but_rejects_bad_points() {
        let (_, _, _, signature) = rfc_records().remove(0);
        assert_eq!(validate_signature_r(&signature[..32]), Ok(()));
        assert_eq!(validate_signature_r(&IDENTITY), Ok(()));
        assert_eq!(validate_signature_r(&[0; 31]), Err(VerificationError::SignatureLength));
        assert!(validate_signature_r(&[0xff; 32]).is_err());

        let mut noncanonical_identity = IDENTITY;
        noncanonical_identity[31] = 0x80;
        assert!(validate_signature_r(&noncanonical_identity).is_err());
        assert_eq!(validate_signature_r(&[0; 32]), Err(VerificationError::SignatureRNotPrimeOrder));
    }

    #[test]
    fn s_validation_enforces_unsigned_canonical_range() {
        const L_MINUS_1: [u8; 32] = [0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
            0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0x10];
        const L: [u8; 32] = [0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
            0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0x10];
        const L_PLUS_1: [u8; 32] = [0xee, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
            0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0x10];
        assert_eq!(validate_signature_s(&[0; 32]), Ok(()));
        assert_eq!(validate_signature_s(&L_MINUS_1), Ok(()));
        assert_eq!(validate_signature_s(&L), Err(VerificationError::SignatureScalarNonCanonical));
        assert_eq!(validate_signature_s(&L_PLUS_1), Err(VerificationError::SignatureScalarNonCanonical));
        assert_eq!(validate_signature_s(&[0; 31]), Err(VerificationError::SignatureScalarLength));
    }

    #[test]
    fn rfc_8032_pure_vectors() {
        let rows = rfc_records();
        assert_eq!(rows.len(), 3);
        for (id, public_key, message, signature) in rows {
            let result = verify_hcomp1(&public_key, &signature, &message);
            println!("RFC_RESULT\t{id}\tACCEPT\t{}", if result.is_ok() { "PASS" } else { "FAIL" });
            assert_eq!(result, Ok(()), "{id}");
        }
    }

    #[test]
    fn signature_and_message_mutations_reject() {
        let (_, public_key, message, signature) = rfc_records().remove(0);
        let mut changed_message = message.clone();
        changed_message.push(1);
        assert_eq!(verify_hcomp1(&public_key, &signature, &changed_message), Err(VerificationError::SignatureEquationMismatch));

        let mut changed_signature = signature.clone();
        changed_signature[63] ^= 1;
        assert!(verify_hcomp1(&public_key, &changed_signature, &message).is_err());

        let (_, wrong_public_key, _, _) = rfc_records().remove(1);
        assert_eq!(verify_hcomp1(&wrong_public_key, &signature, &message), Err(VerificationError::SignatureEquationMismatch));
        assert_eq!(verify_hcomp1(&public_key, &[0; 63], &message), Err(VerificationError::SignatureLength));
    }

    #[test]
    fn identity_a_regression_and_identity_r_equation_are_checked() {
        let (_, _, _, signature) = rfc_records().remove(0);
        assert_eq!(verify_hcomp1(&IDENTITY, &signature, b""), Err(VerificationError::PublicKeyIdentity));

        let identity_r_invalid = wycheproof_record(15);
        assert_eq!(identity_r_invalid[2], "REJECT");
        let public_key = from_hex(&identity_r_invalid[4]);
        let message = from_hex(&identity_r_invalid[5]);
        let signature = from_hex(&identity_r_invalid[6]);
        assert_eq!(validate_signature_r(&signature[..32]), Ok(()));
        assert_eq!(verify_hcomp1(&public_key, &signature, &message), Err(VerificationError::SignatureEquationMismatch));
    }

    #[test]
    fn identity_r_positive_fixture_passes_full_equation_and_negative_mutations_fail() {
        let fields: Vec<_> = IDENTITY_R_POSITIVE.trim().split('\t').collect();
        assert_eq!(fields.len(), 5);
        assert_eq!(fields[0], "synthetic-identity-r-v1");
        assert_eq!(fields[4], "ACCEPT");
        let message = from_hex(fields[1]);
        let public_key = from_hex(fields[2]);
        let signature = from_hex(fields[3]);
        assert_eq!(validate_signature_r(&signature[..32]), Ok(()));
        assert_eq!(&signature[..32], &IDENTITY);
        assert_eq!(verify_hcomp1(&public_key, &signature, &message), Ok(()));

        let mut wrong_s = signature.clone();
        wrong_s[32] = wrong_s[32].wrapping_add(1);
        assert_eq!(verify_hcomp1(&public_key, &wrong_s, &message), Err(VerificationError::SignatureEquationMismatch));

        let mut wrong_message = message.clone();
        wrong_message.push(0);
        assert_eq!(verify_hcomp1(&public_key, &signature, &wrong_message), Err(VerificationError::SignatureEquationMismatch));

        let (_, wrong_public_key, _, _) = rfc_records().remove(1);
        assert_eq!(verify_hcomp1(&wrong_public_key, &signature, &message), Err(VerificationError::SignatureEquationMismatch));

        let mut noncanonical_s = signature.clone();
        noncanonical_s[32..].copy_from_slice(&[
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
            0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
        ]);
        assert_eq!(verify_hcomp1(&public_key, &noncanonical_s, &message), Err(VerificationError::SignatureScalarNonCanonical));
        assert_eq!(verify_hcomp1(&IDENTITY, &signature, &message), Err(VerificationError::PublicKeyIdentity));
        assert_eq!(verify_hcomp1(&public_key, &signature[..63], &message), Err(VerificationError::SignatureLength));
    }

    #[test]
    fn wycheproof_id_validation_rejects_duplicate_missing_unexpected_and_malformed_ids() {
        let valid = expected_wycheproof_ids();
        assert_eq!(validate_wycheproof_ids(valid.iter().map(String::as_str)), Ok(()));

        let mut duplicate = valid.clone();
        duplicate[209] = "1".to_owned();
        assert_eq!(validate_wycheproof_ids(duplicate.iter().map(String::as_str)), Err(WycheproofIdError::Duplicate(1)));

        let mut missing = valid.clone();
        missing.pop();
        assert_eq!(validate_wycheproof_ids(missing.iter().map(String::as_str)), Err(WycheproofIdError::Missing(210)));

        let mut unexpected = valid.clone();
        unexpected[209] = "211".to_owned();
        assert_eq!(validate_wycheproof_ids(unexpected.iter().map(String::as_str)), Err(WycheproofIdError::Unexpected(211)));

        let mut malformed = valid.clone();
        malformed[0] = "not-an-id".to_owned();
        assert_eq!(validate_wycheproof_ids(malformed.iter().map(String::as_str)), Err(WycheproofIdError::Malformed));

        let mut duplicate_plus_missing = valid;
        duplicate_plus_missing[209] = "1".to_owned();
        assert_eq!(duplicate_plus_missing.len(), 210);
        assert_eq!(validate_wycheproof_ids(duplicate_plus_missing.iter().map(String::as_str)), Err(WycheproofIdError::Duplicate(1)));
    }

    #[test]
    fn all_wycheproof_cases_preserve_source_and_project_expectations() {
        let rows: Vec<Vec<&str>> = WYCHEPROOF.lines().map(|line| {
            assert!(!line.is_empty(), "blank Wycheproof rows are malformed");
            let fields: Vec<_> = line.split('\t').collect();
            assert_eq!(fields.len(), 7);
            fields
        }).collect();
        assert_eq!(rows.len(), 210, "full corpus row count");
        validate_wycheproof_ids(rows.iter().map(|fields| fields[0]))
            .unwrap_or_else(|error| panic!("invalid Wycheproof case ID set: {error:?}"));

        let mut total = 0;
        let mut failures = Vec::new();
        let mut actual_accept = 0;
        let mut actual_reject = 0;
        for f in rows {
            let id = f[0];
            let original = f[1];
            let expected = f[2];
            let public_key = from_hex(f[4]);
            let message = from_hex(f[5]);
            let signature = from_hex(f[6]);
            let result = verify_hcomp1(&public_key, &signature, &message);
            let actual = if result.is_ok() { actual_accept += 1; "ACCEPT" } else { actual_reject += 1; "REJECT" };
            let status = match expected {
                "ACCEPT" if actual == "ACCEPT" => "PASS",
                "REJECT" if actual == "REJECT" => "PASS",
                "REVIEW_REQUIRED" => "REVIEW_REQUIRED",
                "ACCEPT" | "REJECT" => {
                    failures.push(format!("tcId {id}: original={original}, expected={expected}, actual={actual}, error={result:?}"));
                    "FAIL"
                }
                _ => panic!("unknown project expectation"),
            };
            println!("WYC_RESULT\t{id}\t{original}\t{expected}\t{actual}\t{status}\t{result:?}");
            total += 1;
        }
        println!("WYC_SUMMARY\t{total}\t{actual_accept}\t{actual_reject}\t{}", failures.len());
        assert_eq!(total, 210, "full corpus inventory");
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }
}
