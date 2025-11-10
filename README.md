# HexXVPN Configuration Decryptor

⚠️ **STATUS: DECRYPTION NOT WORKING PROPERLY**

This tool attempts to decrypt HexXVPN configuration files, but the current implementation produces garbled output.

## Current Status

- ❌ **Decryption is NOT working correctly**
- ❌ Output shows garbled text like `axk@72b`, `"GuArHAH`, etc.
- ❌ These are NOT properly decrypted values
- ❌ The encryption parameters used are incorrect

## Problem

The current implementation uses:
- Password: `HexXVPNPass`
- IV: Fixed bytes from decompiled code
- Algorithm: AES-CBC

However, these parameters produce garbage output, meaning the actual encryption method used by HexXVPN is different.

## Files

- `encrypted_config.json` - Original encrypted configuration
- `hexvpn_decryptor.sh` - Main decryption script (produces garbage output)
- `diagnostic.sh` - Diagnostic tool to analyze encryption
- `quick_decrypt.py` - Quick decryption attempt

## Usage

```bash
# Test current decryption (will show garbled output)
./hexvpn_decryptor.sh test

# Run diagnostic to analyze the encryption
./diagnostic.sh run

# Attempt decryption (produces garbage)
./hexvpn_decryptor.sh decrypt
