## ● Design Approach
To construct a legitimate block, several key considerations were taken into account in my solution. Let's delve into each of these technical aspects.
### Selection of Valid Transactions
The initial phase involved the inclusion of only valid transactions from a transaction pool. Given the maximum block size constraint of 4 MB, an optimization strategy was employed to prioritize transactions that offered the highest profitability to the miner with the least size. This involved the elimination of less profitable transactions.
### Witness Root Hash
The subsequent step necessitated the calculation of the witness commitment for the finalized transactions. However, prior to this, the witness transaction ID of the coinbase transaction was appended to the list at the first position, followed by the computation of the commitment value.
### Coinbase Transaction
EEvery block must contain a unique coinbase transaction, which is incorporated into the block by the miner. This transaction serves to reward the miner with the transaction fees accumulated from the transactions and the current block reward amount. The coinbase transaction comprises a single input, where the input transaction ID is a 32-byte 0x00 value. The output can contain multiple transactions. Typically, the first output is the miner's address, to which the miner sends the collected fees and block reward. The subsequent output's scriptPubKey includes a script that contains the witness commitment of all transactions, as calculated in the previous step.
### Merkle Root Hash
With the transactions commitment value calculated for each transaction (including the coinbase transaction), the next step involved the computation of the Merkle root commitment of the transactions.
### Block Header
To successfully mine a valid block, the calculation of a legitimate block header value is imperative. This value is derived from the block version, the previous block header hash, the Merkle root commitment, and the bits (difficulty in compact size). The process involves repeatedly applying the double SHA-256 hash function to the constructed block header value with a different nonce value (a positive integer up to 4294967295) until the difficulty of the constructed block header value is less than the target difficulty. Upon finding such a value, the iteration ceases, and the value is considered a valid block header. This block is then submitted to the network for inclusion in the blockchain.


## ● Implementation Details
Let's delve into the technical aspects of the following steps:
### Transaction Verification
The transactions were segregated based on segwit and legacy types. For legacy transactions, such as p2pkh and p2sh, signatures and compressed public keys were extracted from the scriptSig. The transaction data was then calculated using these values. The compressed public key was converted into an uncompressed one, and elliptic curve signature verification was employed to calculate the hash. This hash was compared with the double sha256 of the transaction data. If both matched, the input transaction was signed by the user; otherwise, it was considered invalid.

For segwit transactions, the signature and public key found in the witness data were excluded, and the transaction data was calculated. The verification process remained the same. In the case of p2sh or p2wsh transactions, multiple signatures were present, and each signature was verified. If all signatures were valid for that transaction, the input was considered valid; otherwise, it was deemed invalid.
```python
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
```        
### Selection of Eligible Transactions
After selecting verified transactions from the pool, only the most profitable transactions for the miner were included in the block. For this purpose, transactions were sorted based on fees and weight. Transactions with the highest fees and least weight were added accordingly, with a maximum block weight limit of 4 MB.
```python
sorted_total_txs = sorted(total_txs, key=lambda x: (-x['fees'], x['weight']), reverse=True)
```
### Witness Root Commitment and Merkle Root Commitment
Next, the witness commitment and Merkle root commitment of the transactions were calculated. While forming the coinbase transaction, the witness commitment of all transactions, including the coinbase, was calculated and added to the scriptSig field of one of the outputs. After forming the complete coinbase transaction, the Merkle root hash of all transactions was calculated.
```python
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
```
### Calculating Block Header
Finally, with all the necessary information, the block header was calculated using block_version, prev_block_header_hash, merkle_root, time, and bits (difficulty). An infinite loop was created to incrementally add a nonce value to the end of the block_header string and determine if the calculated block_header's difficulty was less than the targeted difficulty. If such a value was found, the loop would break, and the value would be captured as a valid block_header string.
```python
block_header = block_version+prev_block_header_hash+merkle_root+time+bits
while True:
    attempt = block_header + ((nonce).to_bytes(4, byteorder='little').hex())
    attempt_hash = double_sha256(attempt)
    attempt_rev = bytes.fromhex(attempt_hash)[::-1].hex()

    if int(attempt_rev, 16) < int(target, 16):
        block_header = attempt
        break
    nonce += 1
```    


## ● Results and Performance:
In the block mining process, the total transaction fees collected amounted to ```21,614,314``` satoshis, which was derived from a maximum available fee of ```20,616,923``` satoshis in the auto-grader. The block weight was ```3,999,597``` bytes, just below the maximum weight limit of ```4,000,000``` bytes. The final score achieved was ```101``` out of a possible ```100```.
```bash
Collected Fees: 21,614,314 satoshis
Block Weight: 3,999,597 bytes
Maximum Available Fees: 20,616,923 satoshis
Maximum Weight Limit: 4,000,000 bytes
Achieved Score: 101

Total Block Memory Utilization: (3,999,597/4,000,000) * 100 -> 99.989925% ~ 99.99%
```
The results indicate that the block mining strategy employed was highly efficient, with near-optimal utilization of the available block weight. The collected transaction fees exceeded the maximum available fees in the auto-grader, resulting in a score greater than ```100```. The block memory utilization was approximately ```99.99%```, demonstrating effective use of the available block space.


## ● Conclusion:
In summary, the assignment's solution is both straightforward and optimized. However, there is potential for enhancing the transaction selection algorithm's logic to accommodate more transactions and maximize fee collection while efficiently utilizing both used and unused block spaces. A possible approach could involve implementing a variant of the 0/1 Knapsack problem, which would enable the selection of transactions based on their fees and weight, subject to a maximum block size capacity of 4 MB. This optimization could potentially lead to improved transaction inclusion and increased fee collection.

Furthermore, I have included several informative article links below that have significantly contributed to the successful completion of this assignment.

### References:
1. [0/1 Knapsack Problem](https://www.geeksforgeeks.org/0-1-knapsack-problem-dp-10/)
2. [Signing Transactions](https://bitcoin.stackexchange.com/questions/88299/how-to-manually-sign-a-transaction-with-multiple-inputs-and-multiple-outputs)
2. [Creating a Transaction](https://learnmeabitcoin.com/technical/transaction/)
3. [Elliptic Curve Signature Verification](https://learnmeabitcoin.com/technical/cryptography/elliptic-curve/)
4. [Merkle Root](https://learnmeabitcoin.com/technical/block/merkle-root/)
5. [Mining a Valid Block](https://learnmeabitcoin.com/technical/block/)