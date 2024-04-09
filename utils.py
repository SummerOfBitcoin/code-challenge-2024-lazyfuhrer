import hashlib, ecdsa, binascii
from binascii import unhexlify

def extract_public_keys_p2wsh(script):
    script_elements = script.split()
    public_keys = []
    for element in script_elements:
        if element.startswith("02") or element.startswith("03") or element.startswith("04"):
            public_keys.append(element)
    return public_keys

def extract_sigs_p2wsh(witness_arr):
    signatures=[]
    for val in witness_arr:
        if len(val)==0:
            continue
        if val.startswith("30"):
            signatures.append(val)
    return signatures

def extract_public_keys_p2sh(script):
    script_elements = script.split()
    public_keys = []
    for element in script_elements:
        if element.startswith("02") or element.startswith("03") or element.startswith("04"):
            public_keys.append(element)
    return public_keys

def extract_signatures_p2sh(script_hex):
    signatures = []
    # Removing the script length prefix
    if script_hex[:2]=="00":
        script_hex = script_hex[2:]
    # Iterating over the hex string
    i = 0
    while i < len(script_hex):
        # Extracting the length of the signature
        sig_len = int(script_hex[i:i + 2], 16) * 2
        # Extracting the signature
        signature = script_hex[i + 2:i + 2 + sig_len]
        # Check if the length of the extracted data matches the length indicated in the script
        if len(signature) == sig_len:
            # Check if the signature is in DER format (simple validation)
            if signature.startswith('30') and len(signature) >= 70:
                signatures.append(signature)
            # Moving to the next data chunk
            i += 2 + sig_len
        else:
            # If the length doesn't match, move to the next chunk
            i += 2
    return signatures

def decode_p2pkh_scriptsig(script):
    # Extracting signature
    sig_size_bytes = int(script[:2], 16)
    signature = script[2:sig_size_bytes*2+2]

    # Extracting public key size
    pk_size = script[sig_size_bytes*2+2: sig_size_bytes*2+2+2]
    pk_size_bytes = int(pk_size, 16)

    # Extracting public key
    pk = script[-(pk_size_bytes*2):]

    return signature, pk

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
    
def get_full_signature(hex_sig):
    der_signature = unhexlify(hex_sig)    
    # Parse DER signature
    r_length = der_signature[3]
    r = der_signature[4:4+r_length]
    s_length = der_signature[4+r_length+1]
    s = der_signature[4+r_length+2:]

    # Remove leading zero byte from R component if present
    if r[0] == 0:
        r = r[1:]

    # Concatenate R and S components
    signature = r + s
    return signature

def modular_sqrt(a, p):
    return pow(a, (p + 1) // 4, p)

def getFullPubKeyFromCompressed(x_str: str):
    prefix = x_str[0:2]
    x_str = x_str[2:]
    x = int(x_str, 16)
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    y_squared = (x**3 + 7) % p
    y = modular_sqrt(y_squared, p)
    y_str = "%x" % y
    y_is_even = (int(y_str[-1], 16) % 2 == 0)
    if (prefix == "02" and y_is_even == False) or (prefix == "03" and y_is_even == True):
        y = p - y
        y_str = "%x" % y
    return "04" + x_str + y_str

def uncompress_public_key(pubkey):
    prefix = pubkey[0:2]
    if prefix == "02" or prefix == "03":
        pubkey = getFullPubKeyFromCompressed(pubkey)[2:]
    elif prefix == "04":
        pubkey = pubkey[2:]
    return pubkey

def is_sig_valid(txn, hex_sig, comp_pubkey):
    try:
        tx_sha256_hash = hashlib.sha256(bytes.fromhex(txn)).digest().hex()
        sig = get_full_sig(hex_sig).hex()
        pub_key = get_full_public_key(comp_pubkey)

        txn_sha256_b = bytes.fromhex(tx_sha256_hash)
        sig_b = bytes.fromhex(sig)
        pubkey_b = bytes.fromhex(pub_key)

        vk = ecdsa.VerifyingKey.from_string(pubkey_b, curve=ecdsa.SECP256k1)

        if vk.verify(sig_b, txn_sha256_b, hashlib.sha256):
            return True
        else:
            return False
    except Exception as e:
        return False
    

def get_full_public_key(compressed):
    # Split compressed key in to prefix and x-coordinate
    prefix = compressed[0:2]
    if prefix == "04":
        return compressed[2:]
    x = int(compressed[2:], 16)

    # Secp256k1 curve parameters
    p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f

    # Work out y values using the curve equation y^2 = x^3 + 7
    y_sq = (x**3 + 7) % p  # everything is modulo p

    # Secp256k1 is chosen in a special way so that the square root of y is y^((p+1)/4)
    y = pow(y_sq, (p + 1) // 4, p)  # use modular exponentiation

    # Use prefix to select the correct value for y
    # * 02 prefix = y is even
    # * 03 prefix = y is odd
    if prefix == "02" and y % 2 != 0:  # if prefix is 02 and y isn't even, use other y value
        y = (p - y) % p
    if prefix == "03" and y % 2 == 0:  # if prefix is 03 and y is even, use other y value
        y = (p - y) % p

    # Construct the uncompressed public key
    x = format(x, 'x').rjust(64, "0")  # convert to hex and make sure it's 32 bytes (64 characters)
    y = format(y, 'x').rjust(64, "0")
    uncompressed = "04" + x + y

    return uncompressed[2:]

def get_full_sig(der_signature_hex):
    # Convert DER-encoded signature from hex to bytes
    der_signature = binascii.unhexlify(der_signature_hex)
    
    # Extract r and s values from DER-encoded signature
    r_len = der_signature[3]
    r = der_signature[4:4+r_len]
    s_len = der_signature[5+r_len]
    s = der_signature[6+r_len:6+r_len+s_len]
    
    if len(r)>32 and r[0] == 0x00:
        r = r[1:]
    
    if len(s) == 31 and s[0] & 0x80:
        s = b'\x00' + s
    elif len(s) < 32:
        s = b'\x00' * (32 - len(s)) + s
    
    full_signature = r + s
    return full_signature


def calculate_merkle_root(txids):
    if len(txids) == 1:
        return txids[0]
    elif len(txids) % 2 == 1:
        txids.append(txids[-1])

    next_layer = []
    for i in range(0, len(txids), 2):
        pair = txids[i] + txids[i+1]
        next_layer.append(hashlib.sha256(hashlib.sha256(pair).digest()).digest())

    return calculate_merkle_root(next_layer)