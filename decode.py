import base64
import json
import uuid

def decode_token(token):
    _, payload_b64, _ = token.split(b".")
    decoded_payload = base64.b64decode(payload_b64 + b"===")
    return decoded_payload

def format_bytes_as_hex(b):
    return ' '.join(f'{byte:02X}' for byte in b)

def decode_hexadecimal_token(hex_token):
    # Remove non-hexadecimal characters
    clean_hex_token = ''.join(c for c in hex_token if c.isalnum())

    # Extract different parts of the token
    uuid_part = clean_hex_token[:32]
    data1_part = clean_hex_token[32:64]
    int_part = clean_hex_token[64:72]
    data2_part = clean_hex_token[72:104]
    data3_part = clean_hex_token[104:]

    # Convert UUID part to UUID object
    uuid_obj = uuid.UUID(uuid_part[:8] + '-' + uuid_part[8:12] + '-' + uuid_part[12:16] + '-' +
                         uuid_part[16:20] + '-' + uuid_part[20:])

    # Convert hexadecimal parts to bytes
    data1_bytes = bytes.fromhex(data1_part)
    data2_bytes = bytes.fromhex(data2_part)
    data3_bytes = bytes.fromhex(data3_part)

    int_value = int(int_part, 16)

    decoded_data = {
        "UUID": str(uuid_obj),
        "Integer": int_value,
        "Data1": format_bytes_as_hex(data1_bytes),
        "Data2": format_bytes_as_hex(data2_bytes),
        "Data3": format_bytes_as_hex(data3_bytes)
    }

    return decoded_data

# ↓↓↓ Input your token here ↓↓↓
token = ''

# Assume it's a JWT token
if "." in token:
    decoded_payload = decode_token(token.encode())
    decoded_payload_json = json.loads(decoded_payload)
    print("Decoded JWT Payload:")
    print(json.dumps(decoded_payload_json, indent=4))

# Assume it's a hexadecimal string
else:
    decoded_data = decode_hexadecimal_token(token)
    for key, value in decoded_data.items():
        print(f"{key}: {value}")
