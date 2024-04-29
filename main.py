# All the necessary imports 
import os, json, time
from utils import calculate_merkle_root, double_sha256, extract_public_keys_p2sh, extract_public_keys_p2wsh, extract_signatures_p2sh, extract_sigs_p2wsh, get_file_name, natural_txid_to_reverse, reverse_txid_to_natural, get_tx_id, encode_compact_size, is_sig_valid, decode_p2pkh_scriptsig

# Constant values and data structs
directory = './mempool'
total_txs = []
max_block_weight = 4000000
witness_reserved_value = "0000000000000000000000000000000000000000000000000000000000000000"
wt_txid_arr = []
tx_ids_arr = []
total_fees = 0

# Looping through each file
for filename in os.listdir(directory):
    file_path = os.path.join(directory, filename)
    with open(file_path, 'r') as f:
        data = json.load(f)

        # Checking if the transaction is legacy or segwit type
        tx_type = "l"
        for item in data["vin"]:
            if "witness" in item:
                tx_type = "s"     
                break

        # Skipping some files if these conditions are met
        should_skip_file = False
        for item in data["vin"]:
            if (item["prevout"]["scriptpubkey_type"] == "v1_p2tr") or (item["prevout"]["scriptpubkey_type"] == "p2sh" and "witness" in item and len(item["witness"])>2) or (item["prevout"]["scriptpubkey_type"] == "v0_p2wsh" and "witness" in item and len(item["witness"][0])>0):
                should_skip_file = True
                break
        if should_skip_file:
            continue         

        version = data["version"].to_bytes(4, byteorder='little').hex()
        locktime = data["locktime"].to_bytes(4, byteorder='little').hex()

        input_count = encode_compact_size(len(data["vin"])).hex()
        input_stream = ""
        if tx_type=="s":
            input_stream_witness = ""
        input_amount = 0    

        output_count = encode_compact_size(len(data["vout"])).hex()
        output_stream = "" 
        output_amount = 0

        is_tx_valid = True

        non_w_weight = 4 + 4 + len(encode_compact_size(len(data["vin"]))) + len(encode_compact_size(len(data["vout"])))
        w_weight = 0
        if tx_type=="s":
            w_weight = 2

        # looping through inputs to calculate serialized transaction data to get input_stream for tx_id
        for item in data["vin"]:
            natural_tx_id = reverse_txid_to_natural(item["txid"])
            vout = item["vout"].to_bytes(4, byteorder='little').hex()
            script_sig_size = encode_compact_size(len(bytes.fromhex(item["scriptsig"]))).hex()
            script_sig = item["scriptsig"]
            sequence_no = item["sequence"].to_bytes(4, byteorder='little').hex()

            if tx_type=="s":
                if "witness" in item:
                    witness_items_size = encode_compact_size(len(item["witness"])).hex()
                    witness_data = ""

                    w_weight += len(encode_compact_size(len(item["witness"])))

                    for val in item["witness"]:
                        size = encode_compact_size(len(bytes.fromhex(val))).hex()
                        witness_data += size+val

                        w_weight += len(encode_compact_size(len(bytes.fromhex(val)))) + len(bytes.fromhex(val))
                        
                    input_stream_witness += witness_items_size + witness_data    
                else:
                    input_stream_witness += "00"
                    w_weight += 1

            input_stream += natural_tx_id+vout+script_sig_size+script_sig+sequence_no
            input_amount += item["prevout"]["value"]

            script_sig_size_byte = len(encode_compact_size(len(bytes.fromhex(item["scriptsig"]))))
            script_sig_byte = len(bytes.fromhex(item["scriptsig"]))

            non_w_weight += 32+4+4+script_sig_size_byte+script_sig_byte

        # looping theough outputs to calculate serialized transaction data to get output_stream for tx_id
        for item in data["vout"]:
            amount = item["value"].to_bytes(8, byteorder='little').hex()
            script_pubkey_size = encode_compact_size(len(bytes.fromhex(item["scriptpubkey"]))).hex()
            script_pubkey = item["scriptpubkey"]
            output_stream += amount+script_pubkey_size+script_pubkey

            output_amount += item["value"]  

            script_pubkey_size_byte = len(encode_compact_size(len(bytes.fromhex(item["scriptpubkey"]))))
            script_pubkey_byte = len(bytes.fromhex(item["scriptpubkey"]))

            non_w_weight += 8+script_pubkey_size_byte+script_pubkey_byte

        # Verifying signatures for each input in a transaction

        # For legacy transactions 
        if tx_type=="l":
            for item in data["vin"]:
                input_stream_verify = ""
                current = reverse_txid_to_natural(item["txid"])

                natural_tx_id = reverse_txid_to_natural(item["txid"])
                vout = item["vout"].to_bytes(4, byteorder='little').hex()
                sequence_no = item["sequence"].to_bytes(4, byteorder='little').hex()

                # For legacy p2pkh type transactions 
                if item["prevout"]["scriptpubkey_type"] == "p2pkh":

                    script_pubkey_in = item["prevout"]["scriptpubkey"]
                    script_pubkey_in_size = encode_compact_size(len(bytes.fromhex(script_pubkey_in))).hex()
                    script_sig_asm = item["scriptsig_asm"]
                    
                    full_sig, public_key = decode_p2pkh_scriptsig(item["scriptsig"])
                    
                    full_sig_asm = script_sig_asm.split()[1]
                    public_key_asm = script_sig_asm.split()[3]

                    if full_sig==full_sig_asm and public_key==public_key_asm:
                        sig_hash_type = int(full_sig_asm[-2:]).to_bytes(4, byteorder='little').hex()

                    input_current = natural_tx_id+vout+script_pubkey_in_size+script_pubkey_in+sequence_no  

                    for item in data["vin"]:
                        natural_tx_id = reverse_txid_to_natural(item["txid"])
                        if current==natural_tx_id:
                            input_stream_verify += input_current
                        else:
                            vout = item["vout"].to_bytes(4, byteorder='little').hex()
                            sequence_no = item["sequence"].to_bytes(4, byteorder='little').hex()
                            input_stream_verify += natural_tx_id+vout+"00"+sequence_no 

                    tx_input = version+input_count+input_stream_verify+output_count+output_stream+locktime+sig_hash_type
                    if is_sig_valid(tx_input, full_sig_asm[:-2], public_key_asm):
                        continue
                    else:
                        is_tx_valid = False
                        break

                # For legacy p2sh type transactions
                elif item["prevout"]["scriptpubkey_type"] == "p2sh":

                    script_pubkey_in = item["scriptsig_asm"].split()[-1]
                    script_pubkey_in_size = encode_compact_size(len(bytes.fromhex(script_pubkey_in))).hex()
                
                    signatures = extract_signatures_p2sh(item["scriptsig"])
                    public_keys = extract_public_keys_p2sh(item["inner_redeemscript_asm"])

                    input_current = natural_tx_id+vout+script_pubkey_in_size+script_pubkey_in+sequence_no  

                    for item in data["vin"]:
                        natural_tx_id = reverse_txid_to_natural(item["txid"])
                        if current==natural_tx_id:
                            input_stream_verify += input_current
                        else:
                            vout = item["vout"].to_bytes(4, byteorder='little').hex()
                            sequence_no = item["sequence"].to_bytes(4, byteorder='little').hex()
                            input_stream_verify += natural_tx_id+vout+"00"+sequence_no 

                    tx_input = version+input_count+input_stream_verify+output_count+output_stream+locktime

                    passed = 0
                    for sig in signatures:
                        sig_hash_type = int(sig[-2:]).to_bytes(4, byteorder='little').hex()
                        for key in public_keys:
                            if is_sig_valid(tx_input+sig_hash_type, sig[:-2], key):
                                passed += 1
                                break
                    if passed==len(signatures):
                        continue
                    else:   
                        is_tx_valid = False
                        break

        # For segwit transactions
        else:
            txid_vout_inputs = ""
            seq_inputs = ""

            for item in data["vin"]:
                natural_tx_id = reverse_txid_to_natural(item["txid"])
                vout = item["vout"].to_bytes(4, byteorder='little').hex()
                sequence_no = item["sequence"].to_bytes(4, byteorder='little').hex()

                txid_vout_inputs += natural_tx_id+vout
                seq_inputs += sequence_no

            for item in data["vin"]:
                input_stream_verify = ""
                current = reverse_txid_to_natural(item["txid"])

                natural_tx_id = reverse_txid_to_natural(item["txid"])
                vout = item["vout"].to_bytes(4, byteorder='little').hex()
                sequence_no = item["sequence"].to_bytes(4, byteorder='little').hex()
                amount = item["prevout"]["value"].to_bytes(8, byteorder='little').hex()
                
                # For segwit v0_p2wpkh type transactions
                if item["prevout"]["scriptpubkey_type"] == "v0_p2wpkh":

                    pkh = item["prevout"]["scriptpubkey_asm"].split()[-1]
                    pkh_size_hex = encode_compact_size(len(bytes.fromhex(pkh))).hex()
                    scriptcode = "1976a9"+pkh_size_hex+pkh+"88ac"
                    signature = item["witness"][0]
                    public_key = item["witness"][1]
                    sig_hash_type = int(signature[-2:]).to_bytes(4, byteorder='little').hex()
                    
                    # preimage = version + hash256(inputs) + hash256(sequences) + input + scriptcode + amount + sequence + hash256(outputs) + locktime + sighash_type
                    tx_input = version + double_sha256(txid_vout_inputs) + double_sha256(seq_inputs) + natural_tx_id + vout + scriptcode + amount + sequence_no + double_sha256(output_stream) + locktime + sig_hash_type
                    if is_sig_valid(tx_input, signature[:-2], public_key):
                        continue
                    else:
                        is_tx_valid = False
                        break

                # For segwit p2sh type transactions
                elif item["prevout"]["scriptpubkey_type"] == "p2sh":

                    if "witness" in item:
                        pkh = item["inner_redeemscript_asm"].split()[-1]
                        pkh_size_hex = encode_compact_size(len(bytes.fromhex(pkh))).hex()
                        # scriptcode_formula = 1976a914{publickeyhash}88ac
                        scriptcode = "1976a9"+pkh_size_hex+pkh+"88ac"
                        signature = item["witness"][0]
                        public_key = item["witness"][1]
                        sig_hash_type = int(signature[-2:]).to_bytes(4, byteorder='little').hex()
                        
                        # preimage = version + hash256(inputs) + hash256(sequences) + input + scriptcode + amount + sequence + hash256(outputs) + locktime + sighash_type
                        tx_input = version + double_sha256(txid_vout_inputs) + double_sha256(seq_inputs) + natural_tx_id + vout + scriptcode + amount + sequence_no + double_sha256(output_stream) + locktime + sig_hash_type

                        if is_sig_valid(tx_input, signature[:-2], public_key):
                            continue
                        else:
                            is_tx_valid = False
                            break
                    
                    else:
                        script_pubkey_in = item["scriptsig_asm"].split()[-1]
                        script_pubkey_in_size = encode_compact_size(len(bytes.fromhex(script_pubkey_in))).hex()
                        sequence_no = item["sequence"].to_bytes(4, byteorder='little').hex()


                        signatures = extract_signatures_p2sh(item["scriptsig"])
                        public_keys = extract_public_keys_p2sh(item["inner_redeemscript_asm"])

                        input_current = natural_tx_id+vout+script_pubkey_in_size+script_pubkey_in+sequence_no  

                        for item in data["vin"]:
                            natural_tx_id = reverse_txid_to_natural(item["txid"])
                            if current==natural_tx_id:
                                input_stream_verify += input_current
                            else:
                                vout = item["vout"].to_bytes(4, byteorder='little').hex()
                                sequence_no = item["sequence"].to_bytes(4, byteorder='little').hex()
                                input_stream_verify += natural_tx_id+vout+"00"+sequence_no 

                        tx_input = version+input_count+input_stream_verify+output_count+output_stream+locktime

                        passed = 0
                        for sig in signatures:
                            sig_hash_type = int(sig[-2:]).to_bytes(4, byteorder='little').hex()
                            for key in public_keys:
                                if is_sig_valid(tx_input+sig_hash_type, sig[:-2], key):
                                    passed += 1
                                    break
                        if passed==len(signatures):
                            continue
                        else:
                            is_tx_valid = False
                            break
                        
                # For segwit v0_p2wsh type transactions
                elif item["prevout"]["scriptpubkey_type"] == "v0_p2wsh":

                    script_pubkey_in = item["witness"][-1]
                    script_pubkey_in_size = encode_compact_size(len(bytes.fromhex(script_pubkey_in))).hex()
                    scriptcode = script_pubkey_in_size+script_pubkey_in

                    signatures = extract_sigs_p2wsh(item["witness"])
                    public_keys = extract_public_keys_p2wsh(item["inner_witnessscript_asm"])
                    
                    # preimage = version + hash256(inputs) + hash256(sequences) + input + scriptcode + amount + sequence + hash256(outputs) + locktime + sighash_type
                    tx_input = version + double_sha256(txid_vout_inputs) + double_sha256(seq_inputs) + natural_tx_id + vout + scriptcode + amount + sequence_no + double_sha256(output_stream) + locktime

                    passed = 0
                    for sig in signatures:
                        sig_hash_type = int(sig[-2:]).to_bytes(4, byteorder='little').hex()
                        for pk in public_keys:
                            if is_sig_valid(tx_input+sig_hash_type, sig[:-2], pk):
                                passed += 1
                                break
                    if passed==len(signatures):
                        continue
                    else:
                        is_tx_valid = False
                        break

        # Here we proceed further with the current transaction ONLY if it's valid
        if is_tx_valid:  
            weight = (non_w_weight*4) + w_weight
            fees = input_amount-output_amount
            tx_data = version+input_count+input_stream+output_count+output_stream+locktime 

            if tx_type=="s":
                witness_tx_data = version+"00"+"01"+input_count+input_stream+output_count+output_stream+input_stream_witness+locktime
                wt_tx_id = double_sha256(witness_tx_data)

                total_txs.append({"txid": get_tx_id(tx_data), "w_txid": wt_tx_id, "weight": weight, "fees": fees})
            else:
                wt_tx_id = double_sha256(tx_data)

                total_txs.append({"txid": get_tx_id(tx_data), "w_txid": wt_tx_id, "weight": weight, "fees": fees})
        else:
            continue        

# Sorting transactions with most fees and least weights
sorted_total_txs = sorted(total_txs, key=lambda x: (-x['fees'], x['weight']), reverse=True)

# We keep adding transactions untill the max_block_weight is greater than the current transaction weight. And reduce the max_block_weight with the added transaction weight if successful
for item in sorted_total_txs:
    if max_block_weight>item["weight"]:
        max_block_weight -= item["weight"]
        wt_txid_arr.append(item["w_txid"])
        tx_ids_arr.append(item["txid"])
    else:
        continue    
  
wt_txid_arr.insert(0, witness_reserved_value)

txids = [bytes.fromhex(txid) for txid in wt_txid_arr]    
witness_root_hash = calculate_merkle_root(txids).hex()
witness_commitment = double_sha256(witness_root_hash+witness_reserved_value)
# Information for correctly constructing a valid coinbase transaction
version = "01000000"
marker = "00"
flag = "01"
input_count = "01"
input_txid = witness_reserved_value
vout = "ffffffff"
script_sig = "03233708184d696e656420627920416e74506f6f6c373946205b8160a4256c0000946e0100"
script_sig_size = encode_compact_size(len(bytes.fromhex(script_sig))).hex()
seq = "ffffffff"
output_count = "02"
reward = 625000000+total_fees
amount_1 = reward.to_bytes(8, byteorder='little').hex()
script_pubkey_1="76a914edf10a7fac6b32e24daa5305c723f3de58db1bc888ac"
script_pubkey_size_1 = encode_compact_size(len(bytes.fromhex(script_pubkey_1))).hex()
amount_2 = "0000000000000000"
witness_commitment_with_header = "aa21a9ed"+witness_commitment
script_pubkey_2 = "6a"+encode_compact_size(len(bytes.fromhex(witness_commitment_with_header))).hex()+witness_commitment_with_header
script_pubkey_2_size = encode_compact_size(len(bytes.fromhex(script_pubkey_2))).hex()
witness_items = "01"
witness_val = input_txid
witness_val_size = encode_compact_size(len(bytes.fromhex(witness_val))).hex()
locktime = "00000000"
coinbase_tx = version+marker+flag+input_count+input_txid+vout+script_sig_size+script_sig+seq+output_count+amount_1+script_pubkey_size_1+script_pubkey_1+amount_2+script_pubkey_2_size+script_pubkey_2+witness_items+witness_val_size+witness_val+locktime
coinbase_tx_without_witness = version+input_count+input_txid+vout+script_sig_size+script_sig+seq+output_count+amount_1+script_pubkey_size_1+script_pubkey_1+amount_2+script_pubkey_2_size+script_pubkey_2+locktime
tx_ids_arr.insert(0, natural_txid_to_reverse(double_sha256(coinbase_tx_without_witness)))

# Information for correctly creating a valid block
target = "0000ffff00000000000000000000000000000000000000000000000000000000"
block_version = "00000020"
prev_block_header_hash = reverse_txid_to_natural("0000000000000000035a223027a6d55f7dffaab25f06a1a63cec1b5e43ef50d0")

txids = [bytes.fromhex(txid)[::-1] for txid in tx_ids_arr]    
tx_root_hash = calculate_merkle_root(txids).hex()
merkle_root = tx_root_hash
time = int(time.time()).to_bytes(4, byteorder='little').hex()
bits = reverse_txid_to_natural("1f00ffff")
nonce = 0

block_header = block_version+prev_block_header_hash+merkle_root+time+bits

# Looping untill the current block_header header is less than the current difficulty target by incrementally increasing the nonce
while True:
    attempt = block_header + ((nonce).to_bytes(4, byteorder='little').hex())
    attempt_hash = double_sha256(attempt)
    attempt_rev = bytes.fromhex(attempt_hash)[::-1].hex()

    if int(attempt_rev, 16) < int(target, 16):
        block_header = attempt
        break
    nonce += 1

# Storing the result in output.txt
with open("output.txt", "w") as file:
    file.write(block_header + "\n")
    file.write(coinbase_tx + "\n")

    for txid in tx_ids_arr:
        file.write(txid + "\n")