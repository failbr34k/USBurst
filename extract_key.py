#!/usr/bin/env python3
"""Extract and reconstruct device-specific keys from memory dumps.

This module provides utilities for extracting ECDSA private keys from
memory dumps obtained via the DWC3 exploit chain. It uses HKDF key
derivation to reconstruct the device-specific identity keys.

WARNING: This is for authorized research purposes only.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
import sys
from typing import Optional

try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.backends import default_backend

    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


class KeyExtractor:
    """Extract and reconstruct device keys from memory dumps."""

    def __init__(self, device_identifier: bytes):
        self.device_identifier = device_identifier
        self.key_material: Optional[bytes] = None

    def derive_key_hkdf(self, salt: bytes, info: bytes, length: int = 32) -> bytes:
        """Derive a key using HKDF-SHA256.

        Args:
            salt: Optional salt value (can be empty bytes)
            info: Context/application-specific info
            length: Desired key length in bytes

        Returns:
            Derived key bytes
        """
        ikm = self.device_identifier
        if self.key_material:
            ikm = self.key_material

        hkdf = hashlib.new("sha256")
        hkdf.update(ikm)

        okm = b""
        if len(salt) == 0:
            salt = b"\x00" * 32

        prk = hmac.new(salt, ikm, hkdf.name.lower()).digest()

        t = b""
        for i in range((length + 31) // 32):
            t = hmac.new(salt, t + info + bytes([i + 1]), hkdf.name.lower()).digest()
            okm += t

        return okm[:length]

    def extract_ecdsa_key(self, memory_dump: bytes, base_address: int) -> Optional[bytes]:
        """Extract an ECDSA private key from a memory dump.

        Searches the memory dump for the key material at the expected
        location based on the device identifier.

        Args:
            memory_dump: Raw memory dump bytes
            base_address: Base address where dump was taken from

        Returns:
            Extracted private key bytes (32 bytes) or None
        """
        search_pattern = self.device_identifier[:8]
        offset = memory_dump.find(search_pattern)

        if offset == -1:
            return None

        key_offset = offset + 0x40
        if key_offset + 32 > len(memory_dump):
            return None

        candidate = memory_dump[key_offset : key_offset + 32]
        if all(b == 0 for b in candidate):
            return None

        self.key_material = candidate
        return candidate

    def reconstruct_private_key(self, key_bytes: bytes) -> Optional["ec.EllipticCurvePrivateKey"]:
        """Reconstruct a cryptography private key object from raw bytes.

        Args:
            key_bytes: 32-byte private key scalar

        Returns:
            EllipticCurvePrivateKey object or None if cryptography unavailable
        """
        if not HAS_CRYPTO:
            print("[!] cryptography library required (pip install cryptography)")
            return None

        if len(key_bytes) != 32:
            print(f"[!] Invalid key length: {len(key_bytes)} (expected 32)")
            return None

        try:
            private_key = ec.derive_private_key(
                int.from_bytes(key_bytes, "big"),
                ec.SECP256R1(),
                default_backend(),
            )
            return private_key
        except Exception as e:
            print(f"[!] Failed to reconstruct private key: {e}")
            return None

    def export_pem(self, private_key: "ec.EllipticCurvePrivateKey") -> bytes:
        """Export private key in PEM format."""
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def export_der(self, private_key: "ec.EllipticCurvePrivateKey") -> bytes:
        """Export private key in DER format."""
        return private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )


def extract_key_from_memory(
    memory_dump: bytes,
    device_identifier: bytes,
    base_address: int = 0,
) -> Optional[bytes]:
    """Convenience function to extract a private key from a memory dump.

    Args:
        memory_dump: Raw memory dump bytes
        device_identifier: Device-specific identifier bytes
        base_address: Base address of the memory dump

    Returns:
        Extracted private key bytes or None
    """
    extractor = KeyExtractor(device_identifier)
    return extractor.extract_ecdsa_key(memory_dump, base_address)


def reconstruct_key(key_bytes: bytes):
    """Convenience function to reconstruct a private key from raw bytes.

    Args:
        key_bytes: 32-byte private key scalar

    Returns:
        EllipticCurvePrivateKey object or None
    """
    extractor = KeyExtractor(b"")
    return extractor.reconstruct_private_key(key_bytes)


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Extract ECDSA private keys from memory dumps")
    parser.add_argument("dump_file", help="Path to memory dump binary file")
    parser.add_argument("device_id", help="Device identifier hex string")
    parser.add_argument("--base-address", default="0", help="Base address of dump (hex)")
    parser.add_argument("--output", help="Output PEM file path")
    parser.add_argument("--info", default="", help="HKDF info context string")

    args = parser.parse_args()

    try:
        with open(args.dump_file, "rb") as f:
            memory_dump = f.read()
    except FileNotFoundError:
        print(f"[!] Dump file not found: {args.dump_file}", file=sys.stderr)
        return 1

    try:
        device_id = bytes.fromhex(args.device_id)
    except ValueError:
        print(f"[!] Invalid device ID hex: {args.device_id}", file=sys.stderr)
        return 1

    base_addr = int(args.base_address, 0)

    print(f"[*] Analyzing dump: {args.dump_file} ({len(memory_dump)} bytes)")
    print(f"[*] Device ID: {args.device_id}")
    print(f"[*] Base address: 0x{base_addr:x}")

    extractor = KeyExtractor(device_id)
    key_bytes = extractor.extract_ecdsa_key(memory_dump, base_addr)

    if key_bytes is None:
        print("[!] No valid key found in dump")
        return 1

    print(f"[+] Extracted key: {key_bytes.hex()}")

    if HAS_CRYPTO:
        private_key = extractor.reconstruct_private_key(key_bytes)
        if private_key:
            pem = extractor.export_pem(private_key)
            if args.output:
                with open(args.output, "wb") as f:
                    f.write(pem)
                print(f"[+] PEM saved to: {args.output}")
            else:
                print(f"\n{pem.decode()}")

            public_key = private_key.public_key()
            pub_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            print(f"[+] Public key (DER, {len(pub_bytes)} bytes): {pub_bytes.hex()[:64]}...")
    else:
        print("[!] Install cryptography to reconstruct key objects: pip install cryptography")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
