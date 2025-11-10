#!/usr/bin/env python3
import requests
import json
import base64
import hashlib
from Crypto.Cipher import AES

# Quick decrypt function
url = "https://jezvpn.xyz/api/app?json=e37e2c916bd0328ba9d6"
response = requests.get(url)
data = response.json()

print("Downloaded configuration!")
print(f"Servers: {len(data.get('Servers', []))}")
print(f"Tweaks: {len(data.get('Tweaks', []))}")
