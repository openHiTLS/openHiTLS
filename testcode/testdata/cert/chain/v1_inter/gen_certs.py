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
Generate test certificates for v1/v2 intermediate CA rejection tests (Problem 2 fix).

Tests that v1/v2 non-trust-anchor intermediate CAs are rejected, while v1 trust anchors are accepted.

Strategy for v1/v2 certs WITHOUT extensions:
  1. Build a TBS without any extensions using the cryptography library
  2. Sign to get a v3 cert (the library always outputs v3)
  3. Patch the version byte in the TBS DER from 0x02 (v3) to 0x00 (v1) or 0x01 (v2)
  4. Re-sign the patched TBS with the issuer's private key
  5. Assemble the final Certificate SEQUENCE

Output files:
  v3_root.der      - v3 root CA (trust anchor, with BC:CA=TRUE, KU:keyCertSign)
  v1_inter.der     - v1 intermediate WITHOUT extensions, signed by root (TC1)
  v2_inter.der     - v2 intermediate WITHOUT extensions, signed by root (TC2)
  v3_leaf.der      - v3 leaf cert, signed by intermediate's key (for TC1/TC2 chain)
  v1_root.der      - v1 self-signed root WITHOUT extensions (TC3 trust anchor)
  v3_leaf_b.der    - v3 leaf cert, signed by v1 root's key (for TC3 chain)
"""

import os
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding


def gen_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def make_root_cn():
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "V1InterTest"),
        x509.NameAttribute(NameOID.COMMON_NAME, "V1InterTest Root CA"),
    ])


def make_inter_cn():
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "V1InterTest"),
        x509.NameAttribute(NameOID.COMMON_NAME, "V1InterTest Intermediate"),
    ])


def make_leaf_cn():
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "V1InterTest"),
        x509.NameAttribute(NameOID.COMMON_NAME, "V1InterTest Leaf"),
    ])


def make_root_b_cn():
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "V1InterTest"),
        x509.NameAttribute(NameOID.COMMON_NAME, "V1InterTest SelfRoot"),
    ])


def build_ca_tbs(subject, issuer, pub_key, path_length):
    return (
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


def build_leaf_tbs(subject, issuer, pub_key):
    return (
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


def build_no_ext_tbs(subject, issuer, pub_key):
    """Build a TBS without any extensions. Used for v1/v2 certs."""
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(pub_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2024, 1, 1))
        .not_valid_after(datetime.datetime(2050, 12, 31))
    )


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
    if cert_der[0] != 0x30:
        raise ValueError("expected SEQUENCE tag")
    idx = 1
    if cert_der[1] & 0x80:
        idx += 1 + (cert_der[1] & 0x7F)
    else:
        idx += 1
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
    idx = 1
    if cert_der[1] & 0x80:
        idx += 1 + (cert_der[1] & 0x7F)
    else:
        idx += 1
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
    sig_alg_start = idx
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
    sig_val_start = idx
    sig_val_end = len(cert_der)
    return cert_der[sig_alg_start:sig_alg_end], cert_der[sig_val_start:sig_val_end]


def _encode_length(length):
    if length < 0x80:
        return bytes([length])
    elif length < 0x100:
        return bytes([0x81, length])
    elif length < 0x10000:
        return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
    else:
        return bytes([0x83, (length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF])


def build_versioned_cert_no_ext(tbs_builder, signing_key, version):
    """Build a certificate without extensions, with a specific version (0=v1, 1=v2).

    1. Sign a v3 TBS (without extensions) to get a valid cert structure
    2. Extract TBS DER
    3. Patch version byte to desired value
    4. Re-sign patched TBS
    5. Assemble final certificate
    """
    v3_cert = tbs_builder.sign(signing_key, hashes.SHA256())
    v3_der = to_der(v3_cert)

    tbs_der = extract_tbs_der(v3_der)
    patched_tbs = patch_version_in_der(tbs_der, version)

    sig_alg_der, _ = extract_sig_alg_and_value(v3_der)

    new_signature = signing_key.sign(patched_tbs, padding.PKCS1v15(), hashes.SHA256())
    sig_content = b'\x00' + new_signature
    sig_value_der = b'\x03' + _encode_length(len(sig_content)) + sig_content

    inner = patched_tbs + sig_alg_der + sig_value_der
    cert_der = b'\x30' + _encode_length(len(inner)) + inner
    return cert_der


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

    # v3 root CA (trust anchor for TC1/TC2, with BC:CA=TRUE, KU:keyCertSign)
    a_root = build_ca_tbs(root_name, root_name, root_key.public_key(), 2).sign(root_key, hashes.SHA256())
    save(to_der(a_root), "v3_root.der", out_dir)

    # v1 intermediate WITHOUT extensions, signed by root (TC1)
    tbs_inter_no_ext = build_no_ext_tbs(inter_name, root_name, inter_key.public_key())
    save(build_versioned_cert_no_ext(tbs_inter_no_ext, root_key, 0x00), "v1_inter.der", out_dir)

    # v2 intermediate WITHOUT extensions, signed by root (TC2)
    save(build_versioned_cert_no_ext(tbs_inter_no_ext, root_key, 0x01), "v2_inter.der", out_dir)

    # v3 leaf signed by intermediate's key (for TC1/TC2 chain)
    a_leaf = build_leaf_tbs(leaf_name, inter_name, leaf_key.public_key()).sign(inter_key, hashes.SHA256())
    save(to_der(a_leaf), "v3_leaf.der", out_dir)

    # v1 self-signed root WITHOUT extensions (TC3 trust anchor)
    tbs_root_b_no_ext = build_no_ext_tbs(root_b_name, root_b_name, root_b_key.public_key())
    save(build_versioned_cert_no_ext(tbs_root_b_no_ext, root_b_key, 0x00), "v1_root.der", out_dir)

    # v3 leaf signed by v1 root's key (for TC3 chain)
    b_leaf = build_leaf_tbs(leaf_name, root_b_name, leaf_key.public_key()).sign(root_b_key, hashes.SHA256())
    save(to_der(b_leaf), "v3_leaf_b.der", out_dir)

    print("Done.")


if __name__ == "__main__":
    main()
