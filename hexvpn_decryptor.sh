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

# Configuration
HEXXVPN_URL="https://jezvpn.xyz/api/app?json=e37e2c916bd0328ba9d6"
PASSWORD="HexXVPNPass"

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
    clear
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
    
    local missing_deps=()
    
    # Check for Python3
    if ! command -v python3 &> /dev/null; then
        missing_deps+=("python3")
    fi
    
    # Check for curl
    if ! command -v curl &> /dev/null; then
        missing_deps+=("curl")
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        print_warning "Missing dependencies: ${missing_deps[*]}"
        print_info "Installing missing dependencies..."
        pkg update -y
        pkg install -y "${missing_deps[@]}"
    fi
    
    print_status "Dependencies checked and installed"
}

# Download and process configuration
download_config() {
    print_info "Downloading configuration from HexXVPN..."
    
    # Download the raw response
    if curl -s -o raw_response.txt "$HEXXVPN_URL"; then
        print_status "Raw response downloaded successfully"
        
        # Check if download was successful
        if [ -s "raw_response.txt" ]; then
            local file_size=$(wc -c < raw_response.txt)
            print_info "Raw file size: $file_size bytes"
            
            # Process the base64 response
            process_base64_response
        else
            print_error "Downloaded file is empty"
            return 1
        fi
    else
        print_error "Failed to download configuration"
        return 1
    fi
}

# Process the base64 encoded response
process_base64_response() {
    print_info "Processing base64 encoded response..."
    
    # Create Python script to handle the base64 data
    cat > process_response.py << 'EOF'
#!/usr/bin/env python3
import base64
import json
import zlib
import gzip
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib

def try_decode_base64(data):
    """Try to decode the base64 data"""
    try:
        # Remove any whitespace or newlines
        data = data.strip()
        
        # Try standard base64 decode
        decoded = base64.b64decode(data)
        print(f"Base64 decoded successfully: {len(decoded)} bytes")
        return decoded
    except Exception as e:
        print(f"Base64 decode failed: {e}")
        return None

def try_decompress(data):
    """Try different decompression methods"""
    # Try gzip
    try:
        decompressed = gzip.decompress(data)
        print(f"Gzip decompressed: {len(decompressed)} bytes")
        return decompressed
    except:
        pass
    
    # Try zlib
    try:
        decompressed = zlib.decompress(data)
        print(f"Zlib decompressed: {len(decompressed)} bytes")
        return decompressed
    except:
        pass
    
    # Try raw zlib (with different window bits)
    try:
        decompressed = zlib.decompress(data, -zlib.MAX_WBITS)
        print(f"Raw zlib decompressed: {len(decompressed)} bytes")
        return decompressed
    except:
        pass
    
    print("No compression detected, using raw data")
    return data

def decrypt_aes_cbc(encrypted_data, password="HexXVPNPass"):
    """Decrypt AES-CBC encrypted data"""
    try:
        # Fixed IV from decompiled code
        iv = bytes([0x1, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 
                    0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE])
        
        # Generate key using MD5
        key = hashlib.md5(password.encode('utf-8')).digest()
        
        # Create AES cipher
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Decrypt
        decrypted = cipher.decrypt(encrypted_data)
        
        # Remove padding
        try:
            decrypted = unpad(decrypted, AES.block_size)
        except ValueError:
            # Manual padding removal as fallback
            padding_length = decrypted[-1]
            if 0 < padding_length <= 16:
                decrypted = decrypted[:-padding_length]
        
        return decrypted
    except Exception as e:
        print(f"AES decryption failed: {e}")
        return None

def main():
    try:
        # Read the raw response
        with open('raw_response.txt', 'r', encoding='utf-8', errors='ignore') as f:
            raw_data = f.read().strip()
        
        print(f"Read {len(raw_data)} characters from raw response")
        print(f"First 100 chars: {raw_data[:100]}")
        
        # Step 1: Decode base64
        decoded_data = try_decode_base64(raw_data)
        if not decoded_data:
            print("Failed to decode base64")
            return
        
        # Step 2: Try to decompress
        decompressed_data = try_decompress(decoded_data)
        
        # Step 3: Try to decrypt
        print("Attempting decryption...")
        decrypted_data = decrypt_aes_cbc(decompressed_data)
        
        if decrypted_data:
            print(f"Decryption successful: {len(decrypted_data)} bytes")
            
            # Try to parse as JSON
            try:
                json_data = json.loads(decrypted_data.decode('utf-8'))
                print("Successfully parsed as JSON")
                
                # Save the JSON
                with open('encrypted_config.json', 'w', encoding='utf-8') as f:
                    json.dump(json_data, f, indent=2, ensure_ascii=False)
                print("Saved as encrypted_config.json")
                
            except json.JSONDecodeError:
                print("Decrypted data is not JSON, saving as raw text")
                with open('decrypted_raw.txt', 'wb') as f:
                    f.write(decrypted_data)
                print("Saved as decrypted_raw.txt")
                
                # Try to extract JSON from the decrypted data
                try:
                    text_data = decrypted_data.decode('utf-8', errors='ignore')
                    # Look for JSON pattern
                    import re
                    json_pattern = r'\{[^{}]*("[^"]*"\s*:\s*("[^"]*"|\d+|true|false|null)[^{}]*)*\}'
                    matches = re.finditer(json_pattern, text_data, re.DOTALL)
                    
                    for match in matches:
                        try:
                            potential_json = json.loads(match.group())
                            if isinstance(potential_json, dict) and ('Version' in potential_json or 'Servers' in potential_json):
                                print("Found JSON structure in decrypted data!")
                                with open('encrypted_config.json', 'w', encoding='utf-8') as f:
                                    json.dump(potential_json, f, indent=2, ensure_ascii=False)
                                break
                        except:
                            continue
                except Exception as e:
                    print(f"Error processing decrypted data: {e}")
        else:
            print("Decryption failed, trying to process as direct JSON...")
            # Maybe it's already JSON after decompression?
            try:
                json_data = json.loads(decompressed_data.decode('utf-8'))
                print("Decompressed data is JSON!")
                with open('encrypted_config.json', 'w', encoding='utf-8') as f:
                    json.dump(json_data, f, indent=2, ensure_ascii=False)
            except:
                print("Decompressed data is not JSON either")
                # Save the decompressed data for analysis
                with open('decompressed.bin', 'wb') as f:
                    f.write(decompressed_data)
                print("Saved decompressed data as decompressed.bin for analysis")
        
    except Exception as e:
        print(f"Error processing response: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
EOF

    python3 process_response.py
    
    # Clean up
    rm -f process_response.py
    
    if [ -f "encrypted_config.json" ] && [ -s "encrypted_config.json" ]; then
        local json_size=$(wc -c < encrypted_config.json)
        print_status "Configuration processed successfully - Size: $json_size bytes"
        rm -f raw_response.txt
    else
        print_warning "Could not process configuration as expected"
        print_info "Check decrypted_raw.txt or decompressed.bin for manual analysis"
    fi
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
                        print(f"  ❌ {key} - Failed")
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
        if len(text) < 20:
            return False
        try:
            # Check if it's valid Base64 and has typical encrypted length
            decoded = base64.b64decode(text)
            return len(decoded) % 16 == 0  # AES block size
        except:
            return False
    
    def analyze_config(self, data):
        """Analyze the configuration structure"""
        print("\n=== CONFIGURATION ANALYSIS ===")
        
        if isinstance(data, dict):
            print(f"Total keys: {len(data)}")
            
            if 'Version' in data:
                version = data['Version']
                print(f"Version: {version} (encrypted: {self._looks_encrypted(version)})")
            
            if 'Servers' in data:
                servers = data['Servers']
                print(f"Number of Servers: {len(servers)}")
                for i, server in enumerate(servers[:2]):  # Show first 2
                    print(f"  Server {i+1}:")
                    print(f"    Name: {server.get('Name', 'Unknown')}")
                    print(f"    Flag: {server.get('Flag', 'Unknown')}")
                    # Count encrypted fields
                    encrypted_count = sum(1 for v in server.values() if isinstance(v, str) and self._looks_encrypted(v))
                    print(f"    Encrypted fields: {encrypted_count}/{len(server)}")
            
            if 'Tweaks' in data:
                tweaks = data['Tweaks']
                print(f"Number of Tweaks: {len(tweaks)}")
                for i, tweak in enumerate(tweaks[:2]):  # Show first 2
                    print(f"  Tweak {i+1}: {tweak.get('Name', 'Unknown')}")
            
            # Show sample of encrypted fields
            encrypted_fields = []
            for key, value in data.items():
                if isinstance(value, str) and self._looks_encrypted(value):
                    encrypted_fields.append(key)
                    if len(encrypted_fields) >= 5:
                        break
            
            if encrypted_fields:
                print(f"Sample encrypted fields: {encrypted_fields}")
        else:
            print(f"Data type: {type(data)}")

def main():
    print("HexXVPN Configuration Decryptor")
    print("================================\n")
    
    if not CRYPTO_AVAILABLE:
        print("❌ Crypto library not available!")
        print("Please install pycryptodome: pip install pycryptodome")
        return
    
    decryptor = HexXVPNDecryptor()
    
    try:
        # Read encrypted config
        with open('encrypted_config.json', 'r', encoding='utf-8') as f:
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
            
            if 'Tweaks' in decrypted_data:
                tweaks = decrypted_data['Tweaks']
                print(f"Tweaks: {len(tweaks)}")
            
    except FileNotFoundError:
        print("❌ encrypted_config.json not found!")
        print("Please download the configuration first using: ./hexvpn_decryptor.sh download")
    except json.JSONDecodeError as e:
        print(f"❌ Invalid JSON format: {e}")
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

# Install crypto library
install_crypto_lib() {
    print_info "Checking for crypto library..."
    
    if python3 -c "from Crypto.Cipher import AES" &> /dev/null; then
        print_status "Crypto library already installed"
        return 0
    fi
    
    print_info "Installing pycryptodome..."
    if pip install pycryptodome; then
        print_status "pycryptodome installed successfully"
        return 0
    fi
    
    print_error "Failed to install crypto library"
    return 1
}

# Show file information
show_file_info() {
    echo
    print_info "=== FILE INFORMATION ==="
    
    for file in raw_response.txt encrypted_config.json decrypted_config.json decrypted_raw.txt decompressed.bin; do
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
            print(f'Servers: {len(data[\"Servers\"])}')
            if data['Servers']:
                s = data['Servers'][0]
                print('First server keys:', list(s.keys())[:5])
        if 'Tweaks' in data:
            print(f'Tweaks: {len(data[\"Tweaks\"])}')
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
    rm -f raw_response.txt encrypted_config.json decrypted_config.json decrypted_raw.txt decompressed.bin hexvpn_decrypt.py
    print_status "Cleanup completed"
}

# Main execution
main() {
    show_banner
    
    case "${1:-}" in
        "install")
            check_dependencies
            install_crypto_lib
            ;;
        "download")
            download_config
            ;;
        "decrypt")
            if [ ! -f "encrypted_config.json" ]; then
                download_config
            fi
            create_decrypt_script
            python3 hexvpn_decrypt.py
            show_file_info
            ;;
        "clean")
            cleanup_files
            ;;
        "info")
            show_file_info
            ;;
        "all")
            check_dependencies
            install_crypto_lib
            download_config
            create_decrypt_script
            python3 hexvpn_decrypt.py
            show_file_info
            ;;
        *)
            echo "Usage: $0 {install|download|decrypt|clean|info|all}"
            echo
            echo "Commands:"
            echo "  install  - Install dependencies only"
            echo "  download - Download and process configuration"
            echo "  decrypt  - Decrypt downloaded configuration"
            echo "  clean    - Clean up generated files"
            echo "  info     - Show file information"
            echo "  all      - Run complete process (download + decrypt)"
            echo
            echo "Examples:"
            echo "  $0 all        # Complete process"
            echo "  $0 download   # Download config only"
            echo "  $0 decrypt    # Decrypt existing config"
            ;;
    esac
}

# Run main function with all arguments
main "$@"
