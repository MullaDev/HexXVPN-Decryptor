#!/bin/bash
# HexXVPN Configuration Decryptor
# GitHub: https://github.com/MullaDev/HexXVPN-Decryptor
# Author: MullaDev

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored output
print_status() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[*]${NC} $1"
}

# Banner
show_banner() {
    echo -e "${BLUE}"
    echo "=========================================="
    echo "      HexXVPN Configuration Decryptor"
    echo "           GitHub: MullaDev"
    echo "=========================================="
    echo -e "${NC}"
}

# Check dependencies
check_dependencies() {
    print_info "Checking dependencies..."
    
    if ! python3 -c "from Crypto.Cipher import AES" &> /dev/null; then
        print_info "Installing pycryptodome..."
        pip install pycryptodome
    fi
    
    print_status "Dependencies checked"
}

# Create the main decryption script
create_decrypt_script() {
    cat > hexvpn_decrypt.py << 'EOF'
#!/usr/bin/env python3
"""
HexXVPN Configuration Decryptor
Decrypts HexXVPN configuration using AES-CBC with password 'HexXVPNPass'
"""

import json
import base64
import hashlib
import sys
import os

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

class HexXVPNDecryptor:
    def __init__(self, password="HexXVPNPass"):
        self.password = password
        # Fixed IV from decompiled code
        self.iv = bytes([0x1, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 
                         0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE])
        
    def decrypt_aes_cbc(self, encrypted_text):
        """Decrypt AES-CBC encrypted text"""
        if not CRYPTO_AVAILABLE:
            return f"[ERROR: Crypto library not available] - {encrypted_text}"
            
        try:
            # Generate key using MD5
            key = hashlib.md5(self.password.encode('utf-8')).digest()
            
            # Decode Base64
            encrypted_bytes = base64.b64decode(encrypted_text)
            
            # Create AES cipher
            cipher = AES.new(key, AES.MODE_CBC, self.iv)
            
            # Decrypt
            decrypted = cipher.decrypt(encrypted_bytes)
            
            # Remove padding
            try:
                decrypted = unpad(decrypted, AES.block_size)
            except ValueError:
                # Manual padding removal as fallback
                padding_length = decrypted[-1]
                if 0 < padding_length <= 16:
                    decrypted = decrypted[:-padding_length]
                else:
                    # Try to decode without removing padding
                    pass
            
            return decrypted.decode('utf-8', errors='ignore')
            
        except Exception as e:
            return f"[DECRYPTION_ERROR: {str(e)}] - {encrypted_text}"
    
    def decrypt_json(self, data):
        """Recursively decrypt all encrypted fields in JSON"""
        if isinstance(data, dict):
            decrypted_data = {}
            for key, value in data.items():
                if isinstance(value, str) and self._looks_encrypted(value):
                    decrypted_value = self.decrypt_aes_cbc(value)
                    decrypted_data[key] = decrypted_value
                    if not decrypted_value.startswith("[DECRYPTION_ERROR"):
                        print(f"  ✅ {key}: {decrypted_value[:50]}...")
                    else:
                        print(f"  ❌ {key}: {decrypted_value}")
                else:
                    decrypted_data[key] = self.decrypt_json(value)
            return decrypted_data
        
        elif isinstance(data, list):
            return [self.decrypt_json(item) for item in data]
        
        else:
            return data
    
    def _looks_encrypted(self, text):
        """Check if text looks like encrypted Base64"""
        if not isinstance(text, str):
            return False
        if len(text) < 10:  # Reduced minimum length
            return False
        try:
            # Check if it's valid Base64
            decoded = base64.b64decode(text)
            return True
        except:
            return False
    
    def analyze_config(self, data):
        """Analyze the configuration structure"""
        print("\n=== CONFIGURATION ANALYSIS ===")
        
        if isinstance(data, dict):
            print(f"Total keys: {len(data)}")
            
            # Count encrypted fields
            encrypted_count = 0
            total_fields = 0
            
            def count_encrypted(obj):
                nonlocal encrypted_count, total_fields
                if isinstance(obj, dict):
                    for key, value in obj.items():
                        total_fields += 1
                        if isinstance(value, str) and self._looks_encrypted(value):
                            encrypted_count += 1
                        count_encrypted(value)
                elif isinstance(obj, list):
                    for item in obj:
                        count_encrypted(item)
            
            count_encrypted(data)
            print(f"Encrypted fields: {encrypted_count}/{total_fields}")
            
            if 'Version' in data:
                version = data['Version']
                print(f"Version: {version} (encrypted: {self._looks_encrypted(version)})")
            
            if 'Servers' in data:
                servers = data['Servers']
                print(f"Number of Servers: {len(servers)}")
                if servers:
                    server = servers[0]
                    encrypted_server_fields = sum(1 for v in server.values() if isinstance(v, str) and self._looks_encrypted(v))
                    print(f"First server - Encrypted fields: {encrypted_server_fields}/{len(server)}")
            
            if 'Tweaks' in data:
                tweaks = data['Tweaks']
                print(f"Number of Tweaks: {len(tweaks)}")

def main():
    print("HexXVPN Configuration Decryptor")
    print("================================\n")
    
    if not CRYPTO_AVAILABLE:
        print("❌ Crypto library not available!")
        print("Please install pycryptodome: pip install pycryptodome")
        return
    
    decryptor = HexXVPNDecryptor()
    
    # Check for encrypted config file
    config_files = ["encrypted_config.json", "config.json", "hexvpn_config.json"]
    config_file = None
    
    for file in config_files:
        if os.path.exists(file):
            config_file = file
            break
    
    if not config_file:
        print("❌ No encrypted configuration file found!")
        print("Please make sure one of these files exists:")
        for file in config_files:
            print(f"  - {file}")
        return
    
    print(f"📁 Using configuration file: {config_file}")
    
    try:
        # Read encrypted config
        with open(config_file, 'r', encoding='utf-8') as f:
            encrypted_data = json.load(f)
        
        print("📥 Loaded encrypted configuration")
        print("🔓 Starting decryption process...\n")
        
        # Analyze before decryption
        decryptor.analyze_config(encrypted_data)
        
        print("\n🔄 Decrypting fields...")
        # Decrypt the entire JSON
        decrypted_data = decryptor.decrypt_json(encrypted_data)
        
        # Save decrypted config
        with open('decrypted_config.json', 'w', encoding='utf-8') as f:
            json.dump(decrypted_data, f, indent=2, ensure_ascii=False)
        
        print(f"\n✅ Decryption completed!")
        print("💾 Decrypted configuration saved to: decrypted_config.json")
        
        # Show summary
        print("\n=== DECRYPTION SUMMARY ===")
        if isinstance(decrypted_data, dict):
            if 'Version' in decrypted_data:
                version = decrypted_data.get('Version', 'N/A')
                print(f"Version: {version}")
            
            if 'Servers' in decrypted_data:
                servers = decrypted_data['Servers']
                print(f"Servers: {len(servers)}")
                if servers:
                    first_server = servers[0]
                    print(f"First Server: {first_server.get('Name', 'N/A')}")
                    # Show some decrypted values
                    print("Sample decrypted values from first server:")
                    for key in ['SSHHost', 'Username', 'Password']:
                        if key in first_server:
                            value = first_server[key]
                            print(f"  {key}: {value[:50]}...")
            
            if 'Tweaks' in decrypted_data:
                tweaks = decrypted_data['Tweaks']
                print(f"Tweaks: {len(tweaks)}")
                if tweaks:
                    first_tweak = tweaks[0]
                    print(f"First Tweak: {first_tweak.get('Name', 'N/A')}")
            
    except json.JSONDecodeError as e:
        print(f"❌ Invalid JSON format in {config_file}: {e}")
    except Exception as e:
        print(f"❌ Error during decryption: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
EOF

    chmod +x hexvpn_decrypt.py
    print_status "Decryption script created"
}

# Show file information
show_file_info() {
    echo
    print_info "=== FILE INFORMATION ==="
    
    for file in encrypted_config.json config.json hexvpn_config.json decrypted_config.json; do
        if [ -f "$file" ]; then
            local size=$(wc -c < "$file")
            print_info "$file: $size bytes"
        fi
    done
    
    if [ -f "encrypted_config.json" ]; then
        echo
        print_info "=== ENCRYPTED CONFIG PREVIEW ==="
        python3 -c "
import json
try:
    with open('encrypted_config.json', 'r') as f:
        data = json.load(f)
    print('Type:', type(data).__name__)
    if isinstance(data, dict):
        print('Keys:', list(data.keys()))
        if 'Version' in data:
            v = data['Version']
            print(f'Version: {v} (length: {len(v)})')
        if 'Servers' in data:
            servers = data['Servers']
            print(f'Servers: {len(servers)}')
            if servers:
                s = servers[0]
                print('First server has keys:', list(s.keys())[:5])
        if 'Tweaks' in data:
            tweaks = data['Tweaks']
            print(f'Tweaks: {len(tweaks)}')
except Exception as e:
    print('Error:', e)
"
    fi
    
    if [ -f "decrypted_config.json" ]; then
        echo
        print_info "=== DECRYPTED CONFIG PREVIEW ==="
        python3 -c "
import json
try:
    with open('decrypted_config.json', 'r') as f:
        data = json.load(f)
    print('Type:', type(data).__name__)
    if isinstance(data, dict):
        if 'Version' in data:
            print('Version:', data['Version'])
        if 'Servers' in data:
            servers = data['Servers']
            print(f'Servers: {len(servers)}')
            if servers:
                s = servers[0]
                print('First server:')
                for k, v in list(s.items())[:3]:
                    print(f'  {k}: {str(v)[:50]}...')
        if 'Tweaks' in data:
            tweaks = data['Tweaks']
            print(f'Tweaks: {len(tweaks)}')
            if tweaks:
                t = tweaks[0]
                print('First tweak:', t.get('Name', 'Unknown'))
except Exception as e:
    print('Error:', e)
"
    fi
}

# Cleanup files
cleanup_files() {
    print_info "Cleaning up temporary files..."
    rm -f decrypted_config.json hexvpn_decrypt.py
    print_status "Cleanup completed"
}

# Test decryption on a single field
test_decryption() {
    print_info "Testing decryption on sample fields..."
    
    cat > test_decrypt.py << 'EOF'
#!/usr/bin/env python3
import base64
import hashlib
from Crypto.Cipher import AES

def test_decrypt():
    password = "HexXVPNPass"
    iv = bytes([0x1, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 
                0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE])
    
    # Generate key using MD5
    key = hashlib.md5(password.encode('utf-8')).digest()
    
    # Test samples
    test_cases = [
        "vVF0rpq7bdVAa3gsYPi/wg==",
        "9W9iNnW3e3LUB55xDV3Bpg==",
        "Ca4qH95HzbNE4huWD6wgFg=="
    ]
    
    for i, encrypted in enumerate(test_cases):
        try:
            encrypted_bytes = base64.b64decode(encrypted)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(encrypted_bytes)
            
            # Try to remove padding
            try:
                from Crypto.Util.Padding import unpad
                decrypted = unpad(decrypted, AES.block_size)
            except:
                # Manual padding removal
                padding_length = decrypted[-1]
                if 0 < padding_length <= 16:
                    decrypted = decrypted[:-padding_length]
            
            result = decrypted.decode('utf-8', errors='ignore')
            print(f"Test {i+1}: '{encrypted}' -> '{result}'")
            
        except Exception as e:
            print(f"Test {i+1} failed: {e}")

if __name__ == "__main__":
    test_decrypt()
EOF

    python3 test_decrypt.py
    rm -f test_decrypt.py
}

# Main execution
main() {
    show_banner
    
    case "${1:-}" in
        "install")
            check_dependencies
            ;;
        "decrypt")
            check_dependencies
            create_decrypt_script
            python3 hexvpn_decrypt.py
            show_file_info
            ;;
        "test")
            check_dependencies
            test_decryption
            ;;
        "clean")
            cleanup_files
            ;;
        "info")
            show_file_info
            ;;
        *)
            echo "Usage: $0 {install|decrypt|test|clean|info}"
            echo
            echo "Commands:"
            echo "  install - Install dependencies"
            echo "  decrypt - Decrypt the configuration"
            echo "  test    - Test decryption on sample fields"
            echo "  clean   - Clean up generated files"
            echo "  info    - Show file information"
            echo
            echo "Make sure encrypted_config.json exists in the same directory"
            ;;
    esac
}

# Run main function with all arguments
main "$@"
