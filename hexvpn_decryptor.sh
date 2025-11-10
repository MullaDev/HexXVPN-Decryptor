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
    
    # Check Python modules
    if ! python3 -c "import requests" &> /dev/null; then
        print_info "Installing Python requests module..."
        pip install requests
    fi
    
    print_status "Dependencies checked and installed"
}

# Download configuration
download_config() {
    print_info "Downloading configuration from HexXVPN..."
    
    if curl -s -o encrypted_config.json "$HEXXVPN_URL"; then
        print_status "Configuration downloaded successfully"
        
        # Check if download was successful
        if [ -s "encrypted_config.json" ]; then
            local file_size=$(wc -c < encrypted_config.json)
            print_info "File size: $file_size bytes"
        else
            print_error "Downloaded file is empty"
            return 1
        fi
    else
        print_error "Failed to download configuration"
        return 1
    fi
}

# Create decryption script
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
                        print(f"  ✅ {key}")
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
        
        if 'Version' in data:
            print(f"Version: {data['Version']}")
        
        if 'Servers' in data:
            print(f"Number of Servers: {len(data['Servers'])}")
            for i, server in enumerate(data['Servers'][:3]):  # Show first 3
                print(f"  Server {i+1}: {server.get('Name', 'Unknown')}")
                print(f"    Flag: {server.get('Flag', 'Unknown')}")
                if i >= 2 and len(data['Servers']) > 3:
                    print(f"    ... and {len(data['Servers']) - 3} more servers")
                    break
        
        if 'Tweaks' in data:
            print(f"Number of Tweaks: {len(data['Tweaks'])}")
            for i, tweak in enumerate(data['Tweaks'][:3]):  # Show first 3
                print(f"  Tweak {i+1}: {tweak.get('Name', 'Unknown')}")
                print(f"    Mode: {tweak.get('Mode', 'Unknown')}")
                if i >= 2 and len(data['Tweaks']) > 3:
                    print(f"    ... and {len(data['Tweaks']) - 3} more tweaks")
                    break

def main():
    print("HexXVPN Configuration Decryptor")
    print("================================\n")
    
    if not CRYPTO_AVAILABLE:
        print("❌ Crypto library not available!")
        print("Installing required library...")
        os.system("pip install pycryptodome")
        print("Please run the script again.")
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
        if 'Version' in decrypted_data:
            print(f"Version: {decrypted_data.get('Version', 'N/A')}")
        if 'Message' in decrypted_data:
            msg = decrypted_data.get('Message', 'N/A')
            print(f"Message Preview: {msg[:80]}...")
        
    except FileNotFoundError:
        print("❌ encrypted_config.json not found!")
        print("Please download the configuration first.")
    except json.JSONDecodeError:
        print("❌ Invalid JSON format in encrypted_config.json")
    except Exception as e:
        print(f"❌ Error during decryption: {str(e)}")

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
    
    print_warning "pycryptodome installation failed, trying pycrypto..."
    if pip install pycrypto; then
        print_status "pycrypto installed successfully"
        return 0
    fi
    
    print_error "Failed to install crypto libraries"
    return 1
}

# Show file information
show_file_info() {
    echo
    print_info "=== FILE INFORMATION ==="
    
    if [ -f "encrypted_config.json" ]; then
        local enc_size=$(wc -c < encrypted_config.json)
        print_info "encrypted_config.json: $enc_size bytes"
    else
        print_warning "encrypted_config.json: Not found"
    fi
    
    if [ -f "decrypted_config.json" ]; then
        local dec_size=$(wc -c < decrypted_config.json)
        print_info "decrypted_config.json: $dec_size bytes"
        
        # Show preview of decrypted content
        echo
        print_info "=== DECRYPTED CONTENT PREVIEW ==="
        python3 -c "
import json
try:
    with open('decrypted_config.json', 'r') as f:
        data = json.load(f)
    print('Version:', data.get('Version', 'N/A'))
    print('Servers:', len(data.get('Servers', [])))
    print('Tweaks:', len(data.get('Tweaks', [])))
    if 'Servers' in data and data['Servers']:
        print('First Server:', data['Servers'][0].get('Name', 'N/A'))
except Exception as e:
    print('Error:', e)
"
    else
        print_warning "decrypted_config.json: Not found"
    fi
}

# Cleanup files
cleanup_files() {
    print_info "Cleaning up temporary files..."
    rm -f encrypted_config.json decrypted_config.json hexvpn_decrypt.py
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
            install_crypto_lib
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
            echo "  download - Download configuration only"
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
