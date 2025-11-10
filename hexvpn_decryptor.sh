#!/bin/bash
# HexXVPN Decryptor Tool for Termux
# Created for educational purposes

clear
echo "=========================================="
echo "      HexXVPN Configuration Decryptor"
echo "=========================================="
echo

# Check if required packages are installed
check_dependencies() {
    echo "[*] Checking dependencies..."
    
    if ! command -v python3 &> /dev/null; then
        echo "[!] Python3 not found. Installing..."
        pkg install python3 -y
    fi
    
    if ! python3 -c "import requests" &> /dev/null; then
        echo "[!] Python requests module not found. Installing..."
        pip install requests
    fi
    
    if ! python3 -c "import base64" &> /dev/null; then
        echo "[!] Python base64 module not found..."
    fi
    
    if ! command -v curl &> /dev/null; then
        echo "[!] curl not found. Installing..."
        pkg install curl -y
    fi
    
    echo "[+] Dependencies checked"
}

# Download and decrypt the configuration
decrypt_config() {
    echo
    echo "[*] Downloading configuration from HexXVPN server..."
    
    # The update URL
    UPDATE_URL="https://jezvpn.xyz/api/app?json=e37e2c916bd0328ba9d6"
    
    # Download the encrypted JSON
    if curl -s -o encrypted_config.json "$UPDATE_URL"; then
        echo "[+] Configuration downloaded successfully"
    else
        echo "[!] Failed to download configuration"
        exit 1
    fi
    
    echo
    echo "[*] Creating decryption script..."
    
    # Create Python decryption script
    cat > hexvpn_decrypt.py << 'EOF'
import requests
import base64
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib

def decrypt_aes_cbc(encrypted_text, password):
    """
    Decrypt AES-CBC encrypted text using HexXVPN method
    """
    try:
        # Fixed IV from the decompiled code
        iv = bytes([0x1, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE])
        
        # Generate key using MD5 hash of password (as shown in decompiled code)
        key = hashlib.md5(password.encode('utf-8')).digest()
        
        # Decode Base64
        encrypted_bytes = base64.b64decode(encrypted_text)
        
        # Create AES cipher
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Decrypt
        decrypted = cipher.decrypt(encrypted_bytes)
        
        # Unpad and decode
        decrypted = unpad(decrypted, AES.block_size)
        
        return decrypted.decode('utf-8')
    
    except Exception as e:
        return f"[DECRYPTION_ERROR: {str(e)}]"

def decrypt_json_field(data, password):
    """
    Recursively decrypt all encrypted fields in JSON
    """
    if isinstance(data, dict):
        decrypted_data = {}
        for key, value in data.items():
            if isinstance(value, str) and len(value) > 10 and '=' in value:
                # Likely encrypted Base64 string
                try:
                    decrypted_value = decrypt_aes_cbc(value, password)
                    decrypted_data[key] = decrypted_value
                    print(f"[+] Decrypted: {key} -> {decrypted_value[:50]}...")
                except:
                    decrypted_data[key] = value
            else:
                decrypted_data[key] = decrypt_json_field(value, password)
        return decrypted_data
    
    elif isinstance(data, list):
        return [decrypt_json_field(item, password) for item in data]
    
    else:
        return data

def main():
    password = "HexXVPNPass"
    
    try:
        # Read encrypted config
        with open('encrypted_config.json', 'r', encoding='utf-8') as f:
            encrypted_data = json.load(f)
        
        print(f"[*] Starting decryption with password: {password}")
        print("[*] This may take a while for large configurations...")
        print()
        
        # Decrypt the entire JSON
        decrypted_data = decrypt_json_field(encrypted_data, password)
        
        # Save decrypted config
        with open('decrypted_config.json', 'w', encoding='utf-8') as f:
            json.dump(decrypted_data, f, indent=2, ensure_ascii=False)
        
        print()
        print("[+] Decryption completed successfully!")
        print("[+] Decrypted configuration saved to: decrypted_config.json")
        
        # Display some key decrypted values
        print()
        print("=== KEY DECRYPTED VALUES ===")
        if 'Version' in decrypted_data:
            print(f"Version: {decrypted_data.get('Version', 'N/A')}")
        if 'Message' in decrypted_data:
            print(f"Message: {decrypted_data.get('Message', 'N/A')[:100]}...")
        if 'Servers' in decrypted_data and len(decrypted_data['Servers']) > 0:
            print(f"Servers Count: {len(decrypted_data['Servers'])}")
        if 'Tweaks' in decrypted_data:
            print(f"Tweaks Count: {len(decrypted_data['Tweaks'])}")
        
    except Exception as e:
        print(f"[!] Error during decryption: {str(e)}")

if __name__ == "__main__":
    main()
EOF

    # Alternative simpler decryption script if Crypto is not available
    cat > hexvpn_simple_decrypt.py << 'EOF'
import requests
import base64
import json
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os

def simple_decrypt(encrypted_text, password):
    """
    Simple decryption function for HexXVPN
    """
    try:
        # Fixed IV
        iv = bytes([0x1, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE])
        
        # Generate key
        key = hashlib.md5(password.encode()).digest()
        
        # Decode Base64
        encrypted_data = base64.b64decode(encrypted_text)
        
        # Decrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(encrypted_data) + decryptor.finalize()
        
        # Unpad
        unpadder = padding.PKCS7(128).unpadder()
        unpadded = unpadder.update(decrypted) + unpadder.finalize()
        
        return unpadded.decode('utf-8')
    
    except Exception as e:
        return f"[ERROR: {str(e)}]"

def main():
    password = "HexXVPNPass"
    
    try:
        with open('encrypted_config.json', 'r') as f:
            data = json.load(f)
        
        print("[*] Simple decryption test...")
        
        # Test decrypt a few fields
        test_fields = ['Version', 'Message', 'DefUpdateURL']
        
        for field in test_fields:
            if field in data and isinstance(data[field], str):
                decrypted = simple_decrypt(data[field], password)
                print(f"{field}: {decrypted}")
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
EOF

    echo "[+] Decryption scripts created"
    echo
    echo "[*] Installing required Python cryptography library..."
    
    # Install cryptography library
    pip install cryptography
    
    echo
    echo "[*] Starting decryption process..."
    echo
    
    # Run the decryption
    python3 hexvpn_decrypt.py
    
    if [ $? -eq 0 ]; then
        echo
        echo "[+] Decryption completed!"
        echo "[+] Files created:"
        echo "    - encrypted_config.json (original encrypted config)"
        echo "    - decrypted_config.json (decrypted configuration)"
        echo "    - hexvpn_decrypt.py (decryption script)"
    else
        echo
        echo "[!] Main decryption failed, trying simple method..."
        python3 hexvpn_simple_decrypt.py
    fi
}

# Display server information
show_server_info() {
    if [ -f "decrypted_config.json" ]; then
        echo
        echo "=== SERVER INFORMATION ==="
        python3 - << EOF
import json

try:
    with open('decrypted_config.json', 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    if 'Servers' in data:
        print(f"Total Servers: {len(data['Servers'])}")
        print()
        for i, server in enumerate(data['Servers'][:5], 1):  # Show first 5 servers
            print(f"Server {i}: {server.get('Name', 'N/A')}")
            print(f"  Flag: {server.get('Flag', 'N/A')}")
            print(f"  Info: {server.get('Info', 'N/A')}")
            print()
    
    if 'Tweaks' in data:
        print(f"Total Tweaks/Configs: {len(data['Tweaks'])}")
        print()
        for i, tweak in enumerate(data['Tweaks'][:5], 1):  # Show first 5 tweaks
            print(f"Tweak {i}: {tweak.get('Name', 'N/A')}")
            print(f"  Mode: {tweak.get('Mode', 'N/A')}")
            print(f"  Info: {tweak.get('Info', 'N/A')[:50]}...")
            print()

except Exception as e:
    print(f"Error reading decrypted file: {e}")
EOF
    fi
}

# Main menu
main_menu() {
    while true; do
        echo
        echo "=== HEXXVPN DECRYPTOR MENU ==="
        echo "1) Install Dependencies"
        echo "2) Download & Decrypt Configuration"
        echo "3) Show Server Information"
        echo "4) View Decrypted Config"
        echo "5) Cleanup Files"
        echo "6) Exit"
        echo
        read -p "Select option [1-6]: " choice
        
        case $choice in
            1)
                check_dependencies
                ;;
            2)
                decrypt_config
                ;;
            3)
                show_server_info
                ;;
            4)
                if [ -f "decrypted_config.json" ]; then
                    echo
                    echo "=== DECRYPTED CONFIGURATION ==="
                    python3 -c "
import json
try:
    with open('decrypted_config.json', 'r') as f:
        data = json.load(f)
    print(json.dumps(data, indent=2, ensure_ascii=False))
except Exception as e:
    print(f'Error: {e}')
" | head -50
                    echo "... (truncated)"
                else
                    echo "[!] No decrypted configuration found. Run option 2 first."
                fi
                ;;
            5)
                echo "[*] Cleaning up files..."
                rm -f encrypted_config.json decrypted_config.json hexvpn_decrypt.py hexvpn_simple_decrypt.py
                echo "[+] Files cleaned up"
                ;;
            6)
                echo "[+] Exiting HexXVPN Decryptor"
                exit 0
                ;;
            *)
                echo "[!] Invalid option"
                ;;
        esac
    done
}

# Installation script for Termux
installation_script() {
    echo "=========================================="
    echo "    HexXVPN Decryptor - Installation"
    echo "=========================================="
    echo
    echo "[*] This will install all required dependencies"
    echo
    
    # Update and upgrade
    echo "[*] Updating packages..."
    pkg update && pkg upgrade -y
    
    # Install basic tools
    echo "[*] Installing basic tools..."
    pkg install curl wget python3 nano -y
    
    # Install Python packages
    echo "[*] Installing Python packages..."
    pip install requests cryptography
    
    # Upgrade pip
    echo "[*] Upgrading pip..."
    python3 -m pip install --upgrade pip
    
    echo
    echo "[+] Installation completed!"
    echo "[+] You can now run the decryptor script"
    echo
}

# Check if script is being run directly
if [ "$1" == "install" ]; then
    installation_script
else
    # Check if we're in Termux
    if [ -d "/data/data/com.termux/files/usr" ]; then
        echo "[+] Running in Termux environment"
        main_menu
    else
        echo "[!] This script is designed for Termux"
        echo "[*] You can still try to run it if you have Python installed"
        main_menu
    fi
fi
