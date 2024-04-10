import os, json, time
from utils import calculate_merkle_root, double_sha256, extract_public_keys_p2sh, extract_public_keys_p2wsh, extract_signatures_p2sh, extract_sigs_p2wsh, natural_txid_to_reverse, reverse_txid_to_natural, get_tx_id, encode_compact_size, is_sig_valid, decode_p2pkh_scriptsig

directory = './mempool'

witness_reserved_value = "0000000000000000000000000000000000000000000000000000000000000000"
wt_txid_arr = [witness_reserved_value]
tx_ids_arr = [witness_reserved_value]

total_fees = 0

for filename in os.listdir(directory):
    file_path = os.path.join(directory, filename)
    with open(file_path, 'r') as f:
        # print(f"Filename: {filename}")
        data = json.load(f)

        tx_type = "l"
        for item in data["vin"]:
            if "witness" in item:
                tx_type = "s"     
                break

        should_skip_file = False
        for item in data["vin"]:
            if item["prevout"]["scriptpubkey_type"] == "v1_p2tr":
                should_skip_file = True
                break
        if should_skip_file:
            continue        

        should_skip_file = False
        for item in data["vin"]:
            if item["prevout"]["scriptpubkey_type"] == "p2sh" and "witness" in item and len(item["witness"])>2:
                should_skip_file = True
                break
        if should_skip_file:
            continue  

        should_skip_file = False
        for item in data["vin"]:
            if item["prevout"]["scriptpubkey_type"] == "v0_p2wsh" and "witness" in item and len(item["witness"][0])>0:
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
              
        # looping through inputs
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
                    for val in item["witness"]:
                        size = encode_compact_size(len(bytes.fromhex(val))).hex()
                        witness_data += size+val
                    input_stream_witness += witness_items_size + witness_data    
                else:
                    input_stream_witness += "00"

            input_stream += natural_tx_id+vout+script_sig_size+script_sig+sequence_no
 
            input_amount += item["prevout"]["value"]

        #print(input_stream) 

        # looping theough outputs
        for item in data["vout"]:
            amount = item["value"].to_bytes(8, byteorder='little').hex()
            script_pubkey_size = encode_compact_size(len(bytes.fromhex(item["scriptpubkey"]))).hex()
            script_pubkey = item["scriptpubkey"]
            output_stream += amount+script_pubkey_size+script_pubkey

            output_amount += item["value"]  

        #print(output_stream)  


        in_arr = [] 

        if tx_type=="l":
            for item in data["vin"]:

                input_stream_verify = ""
                current = reverse_txid_to_natural(item["txid"])

                if item["prevout"]["scriptpubkey_type"] == "p2pkh":
                    
                    natural_tx_id = reverse_txid_to_natural(item["txid"])
                    vout = item["vout"].to_bytes(4, byteorder='little').hex()
                    sequence_no = item["sequence"].to_bytes(4, byteorder='little').hex()

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
                        # print("valid")
                        continue
                    else:
                        # print("invalid")
                        is_tx_valid = False
                        break

                elif item["prevout"]["scriptpubkey_type"] == "p2sh":
                    
                    natural_tx_id = reverse_txid_to_natural(item["txid"])
                    vout = item["vout"].to_bytes(4, byteorder='little').hex()
                    sequence_no = item["sequence"].to_bytes(4, byteorder='little').hex()

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
                        # print("valid!")
                        continue
                    else:
                        # print("invalid!")    
                        is_tx_valid = False
                        break

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
                
                if item["prevout"]["scriptpubkey_type"] == "v0_p2wpkh":
                    natural_tx_id = reverse_txid_to_natural(item["txid"])
                    vout = item["vout"].to_bytes(4, byteorder='little').hex()
                    sequence_no = item["sequence"].to_bytes(4, byteorder='little').hex()
                    amount = item["prevout"]["value"].to_bytes(8, byteorder='little').hex()

                    pkh = item["prevout"]["scriptpubkey_asm"].split()[-1]
                    pkh_size_hex = encode_compact_size(len(bytes.fromhex(pkh))).hex()
                    # scriptcode_formula = 1976a914{publickeyhash}88ac
                    scriptcode = "1976a9"+pkh_size_hex+pkh+"88ac"
                    signature = item["witness"][0]
                    public_key = item["witness"][1]
                    sig_hash_type = int(signature[-2:]).to_bytes(4, byteorder='little').hex()
                    
                    # preimage = version + hash256(inputs) + hash256(sequences) + input + scriptcode + amount + sequence + hash256(outputs) + locktime + sighash_type
                    tx_input = version + double_sha256(txid_vout_inputs) + double_sha256(seq_inputs) + natural_tx_id + vout + scriptcode + amount + sequence_no + double_sha256(output_stream) + locktime + sig_hash_type
                    if is_sig_valid(tx_input, signature[:-2], public_key):
                        # print("valido")
                        continue
                    else:
                        # print("invalido")
                        is_tx_valid = False
                        break

                elif item["prevout"]["scriptpubkey_type"] == "p2sh":
                    natural_tx_id = reverse_txid_to_natural(item["txid"])
                    vout = item["vout"].to_bytes(4, byteorder='little').hex()
                    sequence_no = item["sequence"].to_bytes(4, byteorder='little').hex()
                    amount = item["prevout"]["value"].to_bytes(8, byteorder='little').hex()

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
                            # print("validx")
                            continue
                        else:
                            # print("invalidx")
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
                            # print("valid!!")
                            continue
                        else:
                            # print("invalid!!")   
                            is_tx_valid = False
                            break
                        

                elif item["prevout"]["scriptpubkey_type"] == "v0_p2wsh":
                    natural_tx_id = reverse_txid_to_natural(item["txid"])
                    vout = item["vout"].to_bytes(4, byteorder='little').hex()
                    sequence_no = item["sequence"].to_bytes(4, byteorder='little').hex()
                    amount = item["prevout"]["value"].to_bytes(8, byteorder='little').hex()

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
                        # print("validy")
                        continue
                    else:
                        # print("invalidy")
                        is_tx_valid = False
                        break

        if is_tx_valid:            
            total_fees += input_amount-output_amount
            tx_data = version+input_count+input_stream+output_count+output_stream+locktime                              
                
            if tx_type=="s":
                witness_tx_data = version+"00"+"01"+input_count+input_stream+output_count+output_stream+input_stream_witness+locktime
                #print("\nWitness TX data:", witness_tx_data)
                wt_tx_id = double_sha256(witness_tx_data)
                wt_txid_arr.append(wt_tx_id)
                # print("\nwTX ID:", wt_tx_id)
                tx_ids_arr.append(wt_tx_id)
            else:
                wt_tx_id = double_sha256(tx_data)
                wt_txid_arr.append(wt_tx_id)
                # print("\nwTX ID:", double_sha256(tx_data))
                tx_ids_arr.append(wt_tx_id)
            
            # print("\nTx data:", tx_data)
            # print("\nTX ID:", get_tx_id(tx_data))
            # print("\nFile name check:", get_file_name(tx_data))
            # print("-------------------------------------------------------------------------")

txids = [bytes.fromhex(txid) for txid in wt_txid_arr]    
witness_root_hash = calculate_merkle_root(txids).hex()
witness_commitment = double_sha256(witness_root_hash+witness_reserved_value)
# print("\nWitness commitment:", witness_commitment)
# print("\nFees:", total_fees)
#*****************coinbase***************************************************************
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
#print("\n",coinbase_tx)
# tx_ids_arr.insert(0, natural_txid_to_reverse(double_sha256(coinbase_tx_without_witness)))
#*****************coinbase***************************************************************
target = "0000ffff00000000000000000000000000000000000000000000000000000000"
block_version = "00000020"
prev_block_header_hash = reverse_txid_to_natural("0000000000000000035a223027a6d55f7dffaab25f06a1a63cec1b5e43ef50d0")
merkle_root = witness_commitment
time = int(time.time()).to_bytes(4, byteorder='little').hex()
bits = reverse_txid_to_natural("1f00ffff")
nonce = 0

block_header = block_version+prev_block_header_hash+merkle_root+time+bits

while True:
    attempt = block_header + ((nonce).to_bytes(4, byteorder='little').hex())
    attempt_hash = double_sha256(attempt)
    attempt_rev = bytes.fromhex(attempt_hash)[::-1].hex()

    if int(attempt_rev, 16) < int(target, 16):
        block_header = attempt
        break
    nonce += 1

with open("output.txt", "w") as file:
    file.write(block_header + "\n")
    file.write(coinbase_tx + "\n")

    for txid in tx_ids_arr:
        file.write(txid + "\n")