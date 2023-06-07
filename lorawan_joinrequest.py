from Crypto.Cipher import AES
import base64
import binascii
import hashlib

def calculate_mic(app_key, app_eui, dev_eui, dev_nonce):
    # Prepare the message to calculate MIC
    msg = bytes.fromhex("00")                     # Join Request MAC header
    msg += bytes.fromhex(app_eui.replace(":", "")) # AppEUI
    msg += bytes.fromhex(dev_eui.replace(":", "")) # DevEUI
    msg += bytes.fromhex(dev_nonce)                # DevNonce
    
    # Calculate MIC using AES-CMAC algorithm
    aes_key = binascii.unhexlify(app_key)
    cmac = aes_cmac(aes_key, msg)
    
    return cmac

def aes_cmac(key, msg):
    # Generate the subkeys
    const_zero = bytearray(16)
    const_zero_block = bytearray(16)
    k1 = aes_cmac_generate_subkey(key, const_zero_block)
    k2 = aes_cmac_generate_subkey(k1, const_zero)
    
    # Padding
    msg_len = len(msg)
    padding_len = 16 - (msg_len % 16)
    if padding_len == 16:
        padding_len = 0
    msg += bytes(padding_len)
    
    # XOR the last block
    last_block = msg[-16:]
    if padding_len > 0:
        last_block[-1] ^= 0x80
    
    # AES-CMAC algorithm
    x = bytes(16)
    n = msg_len // 16 + 1
    for i in range(n - 1):
        block = msg[i*16:(i+1)*16]
        x = xor_bytes(block, x)
        x = aes_encrypt(key, x)
    
    x = xor_bytes(last_block, x)
    x = xor_bytes(x, k1) if n == 1 else xor_bytes(x, k2)
    x = aes_encrypt(key, x)
    
    return x[:4]

def aes_cmac_generate_subkey(key, const):
    const = aes_encrypt(key, const)
    if (const[0] & 0x80) != 0:
        return xor_bytes(const[1:], bytes.fromhex("1B")) # Rb = 0x1B
    else:
        return const[1:]

def xor_bytes(a, b):
    return bytes(i ^ j for i, j in zip(a, b))

def aes_encrypt(key, data):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)

def encode_join_request(app_key, app_eui, dev_eui, dev_nonce):
    # Calculate the MIC
    mic = calculate_mic(app_key, app_eui, dev_eui, dev_nonce)
    
    # Prepare the join request payload
    payload = bytes.fromhex("00")                     # Join Request MAC header
    payload += bytes.fromhex(app_eui.replace(":", "")) # AppEUI
    payload += bytes.fromhex(dev_eui.replace(":", "")) # DevEUI
    payload += bytes.fromhex(dev_nonce)                # DevNonce
    payload += mic
    
    # Base64 encode the payload bytes
    encoded_payload = base64.b64encode(payload).decode('utf-8')
    
    return encoded_payload

# Example usage
app_key = "00112233445566778899AABBCCDDEEFF"
app_eui = "12:34:56:78:9A:BC:DE:F0"
dev_eui = "F0:DE:BC:9A:78:56:34:12"
dev_nonce = "1122"

encoded_join_request = encode_join_request(app_key, app_eui, dev_eui, dev_nonce)
print("Encoded Join Request:", encoded_join_request)

