from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

# Generate a random 16-byte AES key (128-bit)
def generate_key():
    key = get_random_bytes(16)
    print("\n🔑 Generated AES Key (Base64 Encoded):", base64.b64encode(key).decode('utf-8'))
    return key

# AES Encryption Function (with debug prints)
def encrypt_message(message, key):
    print("\n📤 --- ENCRYPTION PROCESS STARTED ---")
    print("Original Plaintext:", message)

    # Step 1: Padding
    padded_data = pad(message.encode('utf-8'), AES.block_size)
    print("🧩 Padded Plaintext Bytes:", padded_data)

    # Step 2: AES Encryption in CBC Mode
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(padded_data)

    # Step 3: Encode IV and Ciphertext in Base64 for readability
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')

    print("🔒 Initialization Vector (Base64):", iv)
    print("🔐 Ciphertext (Base64 Encoded):", ct)

    print("📤 --- ENCRYPTION COMPLETE ---\n")
    return iv + ":" + ct

# AES Decryption Function (with debug prints)
def decrypt_message(encrypted_message, key):
    print("\n📥 --- DECRYPTION PROCESS STARTED ---")
    print("Received Encrypted Message:", encrypted_message)

    # Step 1: Split IV and Cipher Text
    iv_str, ct_str = encrypted_message.split(":")
    iv = base64.b64decode(iv_str)
    ct = base64.b64decode(ct_str)

    print("🔒 Decoded IV (Raw Bytes):", iv)
    print("🔐 Decoded Ciphertext (Raw Bytes):", ct)

    # Step 2: AES Decryption in CBC Mode
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(ct)

    print("🧩 Decrypted (Still Padded) Bytes:", decrypted_data)

    # Step 3: Unpad to get original plaintext
    unpadded = unpad(decrypted_data, AES.block_size)
    print("✅ Final Decrypted Plaintext:", unpadded.decode('utf-8'))

    print("📥 --- DECRYPTION COMPLETE ---\n")
    return unpadded.decode('utf-8')
  
# Helper function to generate and print the AES key (for demo purposes)
def generate_and_print_key():
    import base64
    key = generate_key()
    print("\n🔑 AES Key Generated (Base64 Encoded):", base64.b64encode(key).decode('utf-8'))
    return key

