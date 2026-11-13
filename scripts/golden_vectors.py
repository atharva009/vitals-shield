#!/usr/bin/env python3
"""Golden vectors for the spec Section 3 canonical encodings (plus Protocol C).

Independent reference implementation: Python 3 stdlib only (struct, hashlib).
The expected hex in CanonicalEncodingsTest is copied from this script's output;
the Java code is never used to produce expected values.

Run: python3 scripts/golden_vectors.py
"""
import hashlib
import struct

# ---- fixed inputs (keep in sync with CanonicalEncodingsTest) -----------------
DEVICE_ID = "dev_wearable_019"
BOOTSTRAP_TOKEN = "tok-ABC123"
CRED_ID = "Y3JlZC0wMDE"            # base64url-style credential id
CLINICIAN_ID = "clinician_007"
COSE_KEY_DER = bytes(range(32))           # 00..1f
OLK_CSR_DER = bytes(range(32, 96))        # 20..5f
DEK_SPKI_DER = bytes(range(96, 160))      # 60..9f
OLK_NEW_CSR_DER = bytes(range(160, 224))  # a0..df
ISSUER_KEY_HASH = "a" * 64
SERIAL_NUMBER = "1f2e3d4c5b6a7988"
EPOCH_MS = 1763059200000
NONCE = bytes(range(16))
BOOT_EPOCH = 3


def u32(n: int) -> bytes:
    return struct.pack(">I", n)


def i64(n: int) -> bytes:
    return struct.pack(">q", n)


def utf8_len(s: str) -> bytes:
    b = s.encode("utf-8")
    return u32(len(b)) + b


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def passkey_anchor_bytes() -> bytes:
    # uint32_be(len(cred_id)) || utf8(cred_id) || uint32_be(len(clinician_id)) || utf8(clinician_id)
    #   || sha256(cose_pub_key_der)
    return utf8_len(CRED_ID) + utf8_len(CLINICIAN_ID) + sha256(COSE_KEY_DER)


def provisioning_digest() -> bytes:
    # SHA256(uint32_be(len(device_id)) || utf8(device_id) || sha256(bootstrap_token_ascii) || int64_be(expires_at_ms))
    return sha256(utf8_len(DEVICE_ID) + sha256(BOOTSTRAP_TOKEN.encode("ascii")) + i64(EPOCH_MS))


def dek_enrollment_proof_bytes() -> bytes:
    # uint32_be(len(device_id)) || utf8(device_id) || sha256(bootstrap_token_ascii) || sha256(olk_csr_der)
    return utf8_len(DEVICE_ID) + sha256(BOOTSTRAP_TOKEN.encode("ascii")) + sha256(OLK_CSR_DER)


def dek_anchor_bytes() -> bytes:
    # uint32_be(len(device_id)) || utf8(device_id) || sha256(dek_spki_der) || int64_be(provisioned_at_ms)
    return utf8_len(DEVICE_ID) + sha256(DEK_SPKI_DER) + i64(EPOCH_MS)


def olk_renewal_proof_bytes() -> bytes:
    # uint32_be(len(issuer_key_hash)) || utf8(issuer_key_hash) || uint32_be(len(serial)) || utf8(serial)
    #   || int64_be(issued_at_ms) || random_nonce (16B) || sha256(olk_new_csr_der)
    return (utf8_len(ISSUER_KEY_HASH) + utf8_len(SERIAL_NUMBER) + i64(EPOCH_MS)
            + NONCE + sha256(OLK_NEW_CSR_DER))


def re_enroll_proof_bytes() -> bytes:
    # Section 4 Protocol C step 2:
    # uint32_be(len(device_id)) || utf8(device_id) || int64_be(issued_at_ms) || random_nonce
    #   || int64_be(boot_epoch) || sha256(olk_csr_der)
    return utf8_len(DEVICE_ID) + i64(EPOCH_MS) + NONCE + i64(BOOT_EPOCH) + sha256(OLK_CSR_DER)


VECTORS = [
    ("passkeyAnchorBytes", passkey_anchor_bytes),
    ("provisioningDigest", provisioning_digest),
    ("dekEnrollmentProofBytes", dek_enrollment_proof_bytes),
    ("dekAnchorBytes", dek_anchor_bytes),
    ("olkRenewalProofBytes", olk_renewal_proof_bytes),
    ("reEnrollProofBytes", re_enroll_proof_bytes),
]

if __name__ == "__main__":
    for name, fn in VECTORS:
        print(f"{name} = {fn().hex()}")
