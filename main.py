import os
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from braket.circuits import Circuit
from braket.devices import LocalSimulator

ASSET_REPOSITORY = "repository"
os.makedirs(ASSET_REPOSITORY, exist_ok=True)

def simulate_qkd_bb84():
    device = LocalSimulator()
    circuit = Circuit()
    
    circuit.h(0) 
    circuit.h(1)  
    
    circuit.rx(0, 1.57)  
    circuit.rx(1, 1.57)  
    
    circuit.measure(0)  
    circuit.measure(1)  
    
    result = device.run(circuit, shots=100).result()
    counts = result.measurement_counts
    print(f"QKD Simulation - Measurement Counts: {counts}")
    
    shared_key = "".join([key[0] for key in counts.keys()])[:32] 
    return shared_key

# AES-GCM Encryption
def aes_encrypt(key, plaintext):
   
    iv = os.urandom(12) 
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext, iv, encryptor.tag

# AES-GCM Decryption
def aes_decrypt(key, ciphertext, iv, tag):
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

def store_asset(filename, plaintext, metadata):
    quantum_key = simulate_qkd_bb84()
    quantum_key_bytes = quantum_key.encode('utf-8')  
    
    required_key_length = 32  
    if len(quantum_key_bytes) < required_key_length:
        quantum_key_bytes = quantum_key_bytes.ljust(required_key_length, b'\0')
    elif len(quantum_key_bytes) > required_key_length:
        quantum_key_bytes = quantum_key_bytes[:required_key_length]
    
    # Encrypt asset
    ciphertext, iv, tag = aes_encrypt(quantum_key_bytes, plaintext)
    
    encrypted_path = os.path.join(ASSET_REPOSITORY, f"{filename}.enc")
    with open(encrypted_path, "wb") as f:
        f.write(ciphertext)
    
    # Save metadata
    metadata_path = os.path.join(ASSET_REPOSITORY, f"{filename}.meta")
    metadata["iv"] = iv.hex()
    metadata["tag"] = tag.hex()
    metadata["key"] = quantum_key_bytes.hex() 
    with open(metadata_path, "w") as f:
        json.dump(metadata, f)
    
    print(f"Asset '{filename}' stored successfully.")

# Retrieve and decrypt asset
def retrieve_asset(filename):
    metadata_path = os.path.join(ASSET_REPOSITORY, f"{filename}.meta")
    with open(metadata_path, "r") as f:
        metadata = json.load(f)
    
    encrypted_path = os.path.join(ASSET_REPOSITORY, f"{filename}.enc")
    with open(encrypted_path, "rb") as f:
        ciphertext = f.read()
    
    aes_key = bytes.fromhex(metadata["key"])  
    iv = bytes.fromhex(metadata["iv"])
    tag = bytes.fromhex(metadata["tag"])
    plaintext = aes_decrypt(aes_key, ciphertext, iv, tag)
    
    print(f"Asset '{filename}' retrieved successfully.")
    return plaintext

# Main Function: User Interaction
def main():
    action = input("Would you like to (1) Store a new asset or (2) Retrieve an existing asset? (1/2): ")

    if action == "1":
        asset_name = input("Enter the name for the asset: ")
        asset_metadata = {}
        asset_metadata["owner"] = input("Enter the owner of the asset: ")
        asset_metadata["rights"] = input("Enter the rights for the asset (e.g., Read-Only, Full Access): ")
        asset_metadata["date"] = input("Enter the date of asset creation (YYYY-MM-DD): ")
        
        # Ask user to upload a file
        file_path = input("Enter the path of the file to encrypt: ").strip()  
        try:
            with open(file_path, "rb") as file:
                asset_content = file.read()
            # Store asset
            store_asset(asset_name, asset_content, asset_metadata)
        except FileNotFoundError:
            print("File not found. Please check the file path and try again.")
    
    elif action == "2":
        # User chooses to retrieve an existing asset
        asset_name = input("Enter the name of the asset to retrieve: ")
        
        try:
            # Retrieve and decrypt asset
            retrieved_content = retrieve_asset(asset_name)
            print(f"Decrypted Content: {retrieved_content}")
        except FileNotFoundError:
            print("Asset or metadata not found. Please check the asset name and try again.")
    else:
        print("Invalid choice. Please enter '1' to store or '2' to retrieve.")

# Run the main function
if __name__ == "__main__":
    main()
