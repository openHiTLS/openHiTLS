#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the openHiTLS project.
#
# openHiTLS is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#
#     http://license.coscl.org.cn/MulanPSL2
#
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.
"""
Generate test certificates for TC1-TC5 of the EXTENSIONS_REQUIRE_V3 verification tests.

Strategy: construct v1/v2 certificates with extensions by manually building DER:
  1. Build a v3 TBS using the cryptography library (with extensions)
  2. Patch the version byte in the TBS DER from 0x02 (v3) to 0x00 (v1) or 0x01 (v2)
  3. Re-sign the patched TBS with the issuer's private key
  4. Assemble the final Certificate SEQUENCE: [patched TBS, signatureAlgorithm, signatureValue]

This produces v1/v2 certificates with extensions AND valid signatures, so both OpenSSL
and openHiTLS can parse them. OpenSSL should reject them with
X509_V_ERR_EXTENSIONS_REQUIRE_VERSION_3; openHiTLS should reject them with
HITLS_X509_ERR_VFY_EXTENSIONS_REQUIRE_V3.

Output files:
  a_v3_root.der          - v3 root CA (trust anchor for TC1-TC4)
  a_v1_ext_leaf.der      - TC1: v1 leaf with extensions, valid signature from root
  a_v2_ext_leaf.der      - TC2: v2 leaf with extensions, valid signature from root
  a_v3_inter.der         - v3 intermediate CA, signed by root
  a_v3_leaf.der          - v3 leaf, signed by intermediate (for TC3/TC4 chain)
  a_v1_ext_inter.der     - TC3: v1 intermediate with extensions, valid signature from root
  a_v2_ext_inter.der     - TC4: v2 intermediate with extensions, valid signature from root
  b_v1_ext_root.der      - TC5: v1 root with extensions, valid self-signature
  b_v3_leaf.der          - v3 leaf, signed by root B (for TC5 chain)
"""

import os
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils


def gen_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def make_root_cn():
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "v3exts Test"),
        x509.NameAttribute(NameOID.COMMON_NAME, "v3exts Root CA"),
    ])


def make_inter_cn():
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "v3exts Test"),
        x509.NameAttribute(NameOID.COMMON_NAME, "v3exts Intermediate CA"),
    ])


def make_leaf_cn():
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "v3exts Test"),
        x509.NameAttribute(NameOID.COMMON_NAME, "v3exts Leaf"),
    ])


def make_root_b_cn():
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "v3exts Test"),
        x509.NameAttribute(NameOID.COMMON_NAME, "v3exts Root B CA"),
    ])


def build_ca_tbs(subject, issuer, pub_key, path_length):
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(pub_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2024, 1, 1))
        .not_valid_after(datetime.datetime(2050, 12, 31))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=path_length),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
    )
    return builder


def build_leaf_tbs(subject, issuer, pub_key):
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(pub_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2024, 1, 1))
        .not_valid_after(datetime.datetime(2050, 12, 31))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_encipherment=True,
                content_commitment=False, key_agreement=False,
                key_cert_sign=False, crl_sign=False,
                data_encipherment=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
    )
    return builder


def to_der(cert):
    return cert.public_bytes(serialization.Encoding.DER)


def patch_version_in_der(der_bytes, new_version):
    der = bytearray(der_bytes)
    pattern = bytes([0xA0, 0x03, 0x02, 0x01])
    idx = der.find(pattern)
    if idx < 0:
        raise ValueError("version field pattern not found in DER")
    der[idx + 4] = new_version
    return bytes(der)


def extract_tbs_der(cert_der):
    """Extract the TBSCertificate DER bytes from a Certificate SEQUENCE."""
    # Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    # The outer SEQUENCE tag+length is at position 0.
    # Inside, the first element is TBSCertificate.
    # Parse the outer SEQUENCE
    if cert_der[0] != 0x30:
        raise ValueError("expected SEQUENCE tag")
    # After outer SEQUENCE tag+length, the first child is TBS
    idx = 1
    if cert_der[1] & 0x80:
        idx += 1 + (cert_der[1] & 0x7F)
    else:
        idx += 1
    # Now idx points to the start of the first child (TBSCertificate)
    # Parse TBSCertificate tag+length
    tbs_start = idx
    if cert_der[idx] != 0x30:
        raise ValueError("expected TBS SEQUENCE tag")
    idx += 1
    if cert_der[idx] & 0x80:
        num_len_bytes = cert_der[idx] & 0x7F
        idx += 1
        tbs_content_len = int.from_bytes(cert_der[idx:idx + num_len_bytes], 'big')
        idx += num_len_bytes
    else:
        tbs_content_len = cert_der[idx]
        idx += 1
    tbs_end = idx + tbs_content_len
    return cert_der[tbs_start:tbs_end]


def extract_sig_alg_and_value(cert_der):
    """Extract signatureAlgorithm and signatureValue DER from a Certificate."""
    # Parse outer SEQUENCE
    idx = 1
    if cert_der[1] & 0x80:
        idx += 1 + (cert_der[1] & 0x7F)
    else:
        idx += 1
    # Skip TBSCertificate
    if cert_der[idx] != 0x30:
        raise ValueError("expected TBS SEQUENCE")
    idx += 1
    if cert_der[idx] & 0x80:
        num_len_bytes = cert_der[idx] & 0x7F
        tbs_len = int.from_bytes(cert_der[idx + 1:idx + 1 + num_len_bytes], 'big')
        idx += 1 + num_len_bytes + tbs_len
    else:
        tbs_len = cert_der[idx]
        idx += 1 + tbs_len
    # Now at signatureAlgorithm
    sig_alg_start = idx
    # Skip signatureAlgorithm SEQUENCE
    if cert_der[idx] != 0x30:
        raise ValueError("expected sigAlg SEQUENCE")
    idx += 1
    if cert_der[idx] & 0x80:
        num_len_bytes = cert_der[idx] & 0x7F
        sig_alg_len = int.from_bytes(cert_der[idx + 1:idx + 1 + num_len_bytes], 'big')
        idx += 1 + num_len_bytes + sig_alg_len
    else:
        sig_alg_len = cert_der[idx]
        idx += 1 + sig_alg_len
    sig_alg_end = idx
    # Now at signatureValue BIT STRING
    sig_val_start = idx
    sig_val_end = len(cert_der)
    return cert_der[sig_alg_start:sig_alg_end], cert_der[sig_val_start:sig_val_end]


def build_versioned_cert(tbs_builder, signing_key, version):
    """Build a certificate with a specific version (v1=0, v2=1) but with extensions.

    1. Sign a v3 TBS to get a valid certificate
    2. Extract the TBS DER
    3. Patch the version byte to the desired version
    4. Re-sign the patched TBS
    5. Assemble final certificate
    """
    # First, build a normal v3 cert to get the structure and signature algorithm
    v3_cert = tbs_builder.sign(signing_key, hashes.SHA256())
    v3_der = to_der(v3_cert)

    # Extract TBS and patch version
    tbs_der = extract_tbs_der(v3_der)
    patched_tbs = patch_version_in_der(tbs_der, version)

    # Re-sign the patched TBS
    sig_alg_der, _ = extract_sig_alg_and_value(v3_der)

    # Compute new signature over patched TBS
    new_signature = signing_key.sign(
        patched_tbs,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    # Wrap in BIT STRING: tag=0x03, then length, then 0x00 (unused bits), then signature bytes
    sig_content = b'\x00' + new_signature
    sig_value_der = b'\x03' + _encode_length(len(sig_content)) + sig_content

    # Assemble Certificate SEQUENCE
    inner = patched_tbs + sig_alg_der + sig_value_der
    cert_der = b'\x30' + _encode_length(len(inner)) + inner
    return cert_der


def _encode_length(length):
    if length < 0x80:
        return bytes([length])
    elif length < 0x100:
        return bytes([0x81, length])
    elif length < 0x10000:
        return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
    else:
        return bytes([0x83, (length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF])


def save(der_bytes, filename, out_dir):
    path = os.path.join(out_dir, filename)
    with open(path, "wb") as f:
        f.write(der_bytes)
    print(f"  wrote {filename} ({len(der_bytes)} bytes)")


def main():
    out_dir = os.path.dirname(os.path.abspath(__file__))

    print("Generating keys...")
    root_key = gen_key()
    inter_key = gen_key()
    leaf_key = gen_key()
    root_b_key = gen_key()

    root_name = make_root_cn()
    inter_name = make_inter_cn()
    leaf_name = make_leaf_cn()
    root_b_name = make_root_b_cn()

    print("Generating certificates...")

    # v3 root CA (trust anchor, normal)
    a_root = build_ca_tbs(root_name, root_name, root_key.public_key(), 2).sign(root_key, hashes.SHA256())
    save(to_der(a_root), "a_v3_root.der", out_dir)

    # v3 intermediate CA (normal, signed by root)
    a_inter = build_ca_tbs(inter_name, root_name, inter_key.public_key(), 0).sign(root_key, hashes.SHA256())
    save(to_der(a_inter), "a_v3_inter.der", out_dir)

    # v3 leaf signed by intermediate
    a_leaf = build_leaf_tbs(leaf_name, inter_name, leaf_key.public_key()).sign(inter_key, hashes.SHA256())
    save(to_der(a_leaf), "a_v3_leaf.der", out_dir)

    # TC1: v1 leaf signed by root (with extensions)
    tbs_leaf_direct = build_leaf_tbs(leaf_name, root_name, leaf_key.public_key())
    save(build_versioned_cert(tbs_leaf_direct, root_key, 0x00), "a_v1_ext_leaf.der", out_dir)

    # TC2: v2 leaf signed by root (with extensions)
    save(build_versioned_cert(tbs_leaf_direct, root_key, 0x01), "a_v2_ext_leaf.der", out_dir)

    # TC3: v1 intermediate signed by root (with extensions)
    tbs_inter = build_ca_tbs(inter_name, root_name, inter_key.public_key(), 0)
    save(build_versioned_cert(tbs_inter, root_key, 0x00), "a_v1_ext_inter.der", out_dir)

    # TC4: v2 intermediate signed by root (with extensions)
    save(build_versioned_cert(tbs_inter, root_key, 0x01), "a_v2_ext_inter.der", out_dir)

    # Group b: separate root for TC5
    b_root = build_ca_tbs(root_b_name, root_b_name, root_b_key.public_key(), 2).sign(root_b_key, hashes.SHA256())

    # TC5: v1 root (self-signed, with extensions)
    tbs_root_b = build_ca_tbs(root_b_name, root_b_name, root_b_key.public_key(), 2)
    save(build_versioned_cert(tbs_root_b, root_b_key, 0x00), "b_v1_ext_root.der", out_dir)

    # v3 leaf signed by root B
    b_leaf = build_leaf_tbs(leaf_name, root_b_name, leaf_key.public_key()).sign(root_b_key, hashes.SHA256())
    save(to_der(b_leaf), "b_v3_leaf.der", out_dir)

    print("Done.")


if __name__ == "__main__":
    main()
