
#!/bin/bash
# HexXVPN Encryption Diagnostic
# Author: MullaDev

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() { echo -e "${GREEN}[+]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_error() { echo -e "${RED}[-]${NC} $1"; }
print_info() { echo -e "${BLUE}[*]${NC} $1"; }

show_banner() {
    echo -e "${BLUE}"
    echo "=========================================="
    echo "     HexXVPN Encryption Diagnostic"
    echo "           GitHub: MullaDev"
    echo "=========================================="
    echo -e "${NC}"
}

create_diagnostic_script() {
    cat > diagnostic.py << 'EOF'
#!/usr/bin/env python3
import base64
import hashlib
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import binascii

def test_encryption_methods():
    print("Testing different encryption methods...")
    print("=" * 60)
    
    # Test data from your config
    test_cases = [
        ("vVF0rpq7bdVAa3gsYPi/wg==", "Empty/Default"),
        ("9W9iNnW3e3LUB55xDV3Bpg==", "Username/Password"), 
        ("Ca4qH95HzbNE4huWD6wgFg==", "Version"),
        ("wQNWMW1rPgOA83ko7tJLpg==", "Category")
    ]
    
    methods = [
        {
            "name": "AES-CBC with HexXVPNPass MD5",
            "key": hashlib.md5(b"HexXVPNPass").digest(),
            "iv": bytes([0x1, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE]),
            "mode": AES.MODE_CBC
        },
        {
            "name": "AES-CBC with different password",
            "key": hashlib.md5(b"hexxvpn").digest(),
            "iv": bytes([0x1, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE]),
            "mode": AES.MODE_CBC
        },
        {
            "name": "AES-ECB with HexXVPNPass",
            "key": hashlib.md5(b"HexXVPNPass").digest(),
            "iv": None,
            "mode": AES.MODE_ECB
        }
    ]
    
    for method in methods:
        print(f"\n🔍 Testing: {method['name']}")
        print("-" * 40)
        
        success = 0
        for encrypted_b64, description in test_cases:
            try:
                encrypted = base64.b64decode(encrypted_b64)
                
                if method['mode'] == AES.MODE_CBC:
                    cipher = AES.new(method['key'], method['mode'], method['iv'])
                else:
                    cipher = AES.new(method['key'], method['mode'])
                
                decrypted = cipher.decrypt(encrypted)
                
                # Try padding removal
                try:
                    decrypted = unpad(decrypted, AES.block_size)
                except:
                    # Try manual padding
                    if len(decrypted) > 0:
                        last_byte = decrypted[-1]
                        if 0 < last_byte <= 16 and all(b == last_byte for b in decrypted[-last_byte:]):
                            decrypted = decrypted[:-last_byte]
                
                result = decrypted.decode('utf-8', errors='ignore')
                
                # Check if result looks reasonable
                is_reasonable = (
                    len(result) > 0 and 
                    not any(c in result for c in ['\x00', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07']) and
                    all(32 <= ord(c) <= 126 for c in result[:min(10, len(result))])
                )
                
                status = "✅" if is_reasonable else "❌"
                print(f"{status} {description}: '{result}'")
                if is_reasonable:
                    success += 1
                    
            except Exception as e:
                print(f"❌ {description}: Error - {e}")
        
        print(f"Results: {success}/{len(test_cases)} reasonable outputs")

def analyze_encrypted_fields():
    print(f"\n\n📊 Analyzing encrypted fields structure...")
    print("=" * 60)
    
    try:
        with open('encrypted_config.json', 'r') as f:
            data = json.load(f)
        
        # Analyze field patterns
        field_stats = {}
        
        def analyze_object(obj, path=""):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    current_path = f"{path}.{k}" if path else k
                    if isinstance(v, str) and len(v) > 10:
                        try:
                            decoded = base64.b64decode(v)
                            field_stats[current_path] = {
                                'length': len(v),
                                'decoded_length': len(decoded),
                                'is_multiple_16': len(decoded) % 16 == 0,
                                'sample': v[:20] + "..." if len(v) > 20 else v
                            }
                        except:
                            pass
                    analyze_object(v, current_path)
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    analyze_object(item, f"{path}[{i}]")
        
        analyze_object(data)
        
        print("Field analysis:")
        for field, stats in list(field_stats.items())[:10]:  # Show first 10
            print(f"  {field}:")
            print(f"    Length: {stats['length']} chars, Decoded: {stats['decoded_length']} bytes")
            print(f"    Multiple of 16: {stats['is_multiple__16']}")
            print(f"    Sample: {stats['sample']}")
            
    except Exception as e:
        print(f"Error analyzing: {e}")

def check_for_common_patterns():
    print(f"\n\n🕵️ Checking for common encryption patterns...")
    print("=" * 60)
    
    common_passwords = ["HexXVPNPass", "hexxvpn", "HexXVPN", "vpn", "password", "123456"]
    common_ivs = [
        bytes([0x1, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE]),
        bytes([0] * 16),
        bytes([1] * 16),
        hashlib.md5(b"HexXVPNPass").digest()[:16]
    ]
    
    test_data = "9W9iNnW3e3LUB55xDV3Bpg=="  # Username field
    
    for password in common_passwords:
        for iv in common_ivs:
            try:
                # Try different key derivation methods
                keys_to_try = [
                    hashlib.md5(password.encode()).digest(),
                    hashlib.sha256(password.encode()).digest()[:16],  # AES-128
                    hashlib.sha256(password.encode()).digest()[:32],  # AES-256
                    password.encode().ljust(16, b'\0')[:16],  # Padding
                    password.encode().ljust(32, b'\0')[:32]   # Padding for AES-256
                ]
                
                for key in keys_to_try:
                    try:
                        encrypted = base64.b64decode(test_data)
                        cipher = AES.new(key, AES.MODE_CBC, iv)
                        decrypted = cipher.decrypt(encrypted)
                        
                        # Try to remove padding
                        try:
                            decrypted = unpad(decrypted, AES.block_size)
                        except:
                            pass
                        
                        result = decrypted.decode('utf-8', errors='ignore')
                        
                        # Check if it looks like real data
                        if (len(result) >= 3 and 
                            all(32 <= ord(c) <= 126 for c in result) and
                            not any(c in result for c in ['\x00', '\x01', '\x02'])):
                            
                            print(f"🎯 Potential match!")
                            print(f"   Password: {password}")
                            print(f"   Key: {binascii.hexlify(key).decode()}")
                            print(f"   IV: {binascii.hexlify(iv).decode()}")
                            print(f"   Result: '{result}'")
                            return
                            
                    except Exception:
                        continue
                        
            except Exception as e:
                continue
    
    print("No common patterns found with basic methods")

if __name__ == "__main__":
    test_encryption_methods()
    analyze_encrypted_fields() 
    check_for_common_patterns()
    
    print(f"\n💡 Recommendations:")
    print("1. The current method produces garbled output - encryption parameters are wrong")
    print("2. Need to analyze the actual APK more carefully")
    print("3. Might need to hook into the running app to see real decryption")
    print("4. Could be using a different algorithm (ChaCha20, custom cipher, etc.)")
EOF

    chmod +x diagnostic.py
    print_status "Diagnostic script created"
}

main() {
    show_banner
    
    case "${1:-}" in
        "run")
            create_diagnostic_script
            python3 diagnostic.py
            ;;
        "clean")
            rm -f diagnostic.py
            print_status "Cleaned up"
            ;;
        *)
            echo "Usage: $0 {run|clean}"
            echo "  run   - Run encryption diagnostic"
            echo "  clean - Clean up diagnostic files"
            ;;
    esac
}

main "$@"
