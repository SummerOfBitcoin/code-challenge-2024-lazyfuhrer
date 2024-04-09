import os
import json
import hashlib

directory = './mempool'

count = 0

def double_sha256(hex_data):
    binary_data = bytes.fromhex(hex_data)
    sha256_hash = hashlib.sha256(binary_data).digest()
    sha256_hash = hashlib.sha256(sha256_hash).hexdigest()
    return sha256_hash

def natural_txid_to_reverse(txid_normal):
    reversed_bytes = bytes.fromhex(txid_normal)[::-1]
    reversed_hex = reversed_bytes.hex()
    return reversed_hex

def reverse_txid_to_natural(txid_reversed):
    txid_bytes_reversed = bytes.fromhex(txid_reversed)[::-1]
    txid_natural = txid_bytes_reversed.hex()
    return txid_natural    

def get_tx_id(hex_data):
    return natural_txid_to_reverse(double_sha256(hex_data))

def get_file_name(tx_data):
    tx_id = get_tx_id(tx_data)
    tx_id_bytes = bytes.fromhex(tx_id)
    sha256_hash = hashlib.sha256(tx_id_bytes).hexdigest()
    return sha256_hash

def encode_compact_size(num):
    if num < 0xFD:
        return bytes([num])
    elif num <= 0xFFFF:
        return b'\xFD' + num.to_bytes(2, 'little')
    elif num <= 0xFFFFFFFF:
        return b'\xFE' + num.to_bytes(4, 'little')
    else:
        return b'\xFF' + num.to_bytes(8, 'little')  

for filename in os.listdir(directory):
    file_path = os.path.join(directory, filename)
    with open(file_path, 'r') as f:
        print(f"Filename: {filename}")
        data = json.load(f)
        version = data["version"].to_bytes(4, byteorder='little').hex()
        locktime = data["locktime"].to_bytes(4, byteorder='little').hex()

        input_count = encode_compact_size(len(data["vin"])).hex()
        input_stream = ""

        output_count = encode_compact_size(len(data["vout"])).hex()
        output_stream = ""

        input_val = 0
        output_val = 0

        # looping through inputs
        for item in data["vin"]:
            natural_tx_id = reverse_txid_to_natural(item["txid"])
            vout = item["vout"].to_bytes(4, byteorder='little').hex()
            script_sig_size = encode_compact_size(len(bytes.fromhex(item["scriptsig"]))).hex()
            script_sig = item["scriptsig"]
            sequence_no = item["sequence"].to_bytes(4, byteorder='little').hex()
            input_stream += natural_tx_id+vout+script_sig_size+script_sig+sequence_no

            input_val += item["prevout"]["value"]

        #print(input_stream) 

        # looping theough outputs
        for item in data["vout"]:
            amount = item["value"].to_bytes(8, byteorder='little').hex()
            script_pubkey_size = encode_compact_size(len(bytes.fromhex(item["scriptpubkey"]))).hex()
            script_pubkey = item["scriptpubkey"]
            output_stream += amount+script_pubkey_size+script_pubkey

            output_val += item["value"]

        #print(output_stream)  

        tx_data = version+input_count+input_stream+output_count+output_stream+locktime
        print("\nTx data:", tx_data)
        print("\nTX ID:", get_tx_id(tx_data))
        print("\nFile name check:", get_file_name(tx_data))
        print("-------------------------------------------------------------------------")

        if get_file_name(tx_data)+".json" != filename:
            count += 1    
print(count)