from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import struct
import base64

# Function to encode payload data
def encode_payload(data):
    encoded_data = base64.b64encode(data)
    return encoded_data

# Function to encode LoRaWAN 1.1 packet
def encode_lorawan_packet(dev_eui, app_eui, app_key, payload):
    app_key_bytes = bytes.fromhex(app_key)
    dev_eui_bytes = bytes.fromhex(dev_eui)
    app_eui_bytes = bytes.fromhex(app_eui)

    dev_nonce = struct.pack('>H', 0x0102)  # Replace with actual device nonce

    packet = dev_nonce + dev_eui_bytes + app_eui_bytes

    packet += bytes.fromhex('00')  # FCtrl

    # Calculate MIC
    padded_packet = pad(packet, AES.block_size)  # Pad the packet to the block size
    mic = calculate_mic(app_key_bytes, padded_packet)
    packet += mic

    # Encode payload
    encoded_payload = encode_payload(payload)
    packet += encoded_payload

    return packet

# Function to calculate MIC (Message Integrity Code)
def calculate_mic(app_key, packet):
    mic = bytes.fromhex('00000000')  # Initial MIC value

    # Calculate MIC using AES-128 CMAC algorithm in ECB mode
    aes128_cmac = AES.new(app_key, AES.MODE_ECB)
    for i in range(0, len(packet), AES.block_size):
        block = packet[i:i + AES.block_size]
        mic = xor_bytes(mic, aes128_cmac.encrypt(block))

    return mic

# Function to perform XOR operation on two byte arrays
def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

# Example usage
dev_eui = '0011223344556677'
app_eui = '1122334455667788'
app_key = '2B7E151628AED2A6ABF7158809CF4F3C'
payload = b'Hello, LoRaWAN!'

lorawan_packet = encode_lorawan_packet(dev_eui, app_eui, app_key, payload)
print('Encoded LoRaWAN packet:', base64.b16encode(lorawan_packet).decode('utf-8'))
