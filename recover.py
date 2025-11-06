#!/usr/bin/env python3
"""
Disaster Recovery Restoration Script
Requires threshold number of key shares to decrypt and restore
"""

import os
import sys
import json
import argparse
from typing import List, Tuple
from Crypto.Protocol.SecretSharing import Shamir
from Crypto.Cipher import AES

class DRRestore:
    def __init__(self):
        self.shares = []

    def load_share_from_file(self, share_file: str) -> Tuple[int, bytes]:
        """Load share from JSON file"""
        with open(share_file, 'r') as f:
            share_data = json.load(f)

        return (share_data['share_index'], bytes.fromhex(share_data['share']))

    def collect_shares_from_files(self, share_files: List[str]) -> bytes:
        """Collect key shares from JSON files and reconstruct key"""
        print(f"Loading {len(share_files)} shares...")

        shares = []
        for share_file in share_files:
            share = self.load_share_from_file(share_file)
            shares.append(share)
            print(f"  Loaded share {share[0]} from {share_file}")

        # Reconstruct the key
        print("Reconstructing encryption key...")
        key = Shamir.combine(shares)
        return key

    def decrypt_backup(self, encrypted_file: str, key: bytes, output_file: str):
        """Decrypt the backup file"""
        print(f"Decrypting {encrypted_file}...")

        with open(encrypted_file, 'rb') as f:
            nonce = f.read(16)
            tag = f.read(16)
            ciphertext = f.read()

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        data = cipher.decrypt_and_verify(ciphertext, tag)

        with open(output_file, 'wb') as f:
            f.write(data)

        print(f"Decrypted backup saved to: {output_file}")

    def restore(self, encrypted_file: str, share_files: List[str], output_file: str):
        """Main restoration flow"""
        # Collect shares and reconstruct key
        key = self.collect_shares_from_files(share_files)

        # Decrypt backup
        self.decrypt_backup(encrypted_file, key, output_file)

        print("Restoration complete!")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Decrypt and restore a backup using Shamir secret shares')
    parser.add_argument('--encrypted-file', required=True, help='Path to encrypted backup file (.enc)')
    parser.add_argument('--share', action='append', required=True, help='Path to share JSON file (use multiple times)')
    parser.add_argument('--output', required=True, help='Output path for decrypted backup')

    args = parser.parse_args()

    restore = DRRestore()
    restore.restore(args.encrypted_file, args.share, args.output)