# LoRaWAN-1.1.x-encoder
A python script for encoding LoRaWAN 1.1 packets using the "paho-mqtt" library
## Description :
The script encodes a LoRaWAN 1.1 packet by first converting the device EUI, application EUI, and application key from hex strings to byte arrays. It then constructs the packet according to the LoRaWAN 1.1 specification, including the device nonce, EUIs, FCtrl, and payload. Finally, it calculates the MIC using the AES-128 CMAC algorithm and appends it to the packet. The payload is encoded using Base64 before being appended to the packet.
The `dev_nonce` variable is set to a fixed value for demonstration purposes, but in a real application, you would generate a unique random value for each message.
## Setup :
- Ubuntu 20.04
- Python 3.8.10
- pip 20.0.2
## Getting started :
Install requirements:
```
pip3 install -r requirements.txt 
```
Run script : 
```
python3 lorawan_encoder.py
```
