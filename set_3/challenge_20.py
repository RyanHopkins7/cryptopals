from challenge_18 import aes_ctr_encrypt
from os import urandom
from base64 import b64decode

def aes_ctr_stream_decrypt(ct, stream):
    pt = bytearray()
    ctr = 0
    while len(pt) < len(ct):
        for i, b in enumerate(stream):
            pt_idx = ctr*16+i
            if pt_idx < len(ct):
                pt.append(b ^ ct[pt_idx])
            else:
                break
        ctr += 1
    return pt

# Iterate over all possible key values and select the one which scores highest
# Source: set 1 challenge 3! Essentially the same as breaking single byte xor
def decodeSingleByteXOR(ct):
    p = ''
    best_score = 0
    key = None

    for cand in range(0, 256):
        msg_bytes = bytes(b ^ cand for b in ct)
        utf8_msg = msg_bytes.decode('utf-8', errors='replace').lower()
        
        hist = {}
        for c in utf8_msg:
            # group all chars which are not a space, period, or letter together
            if ord(c) != 0x20 and ord(c) != 0x2e and (ord(c) < 0x61 or ord(c) > 0x7a):
                c = 'nonalpha'

            if c in hist:
                hist[c] += 1
            else:
                hist[c] = 1

        # In English text, space is the most common character
        # Source: https://en.wikipedia.org/wiki/Letter_frequency
        # So, here we're looking for the key which produces the most spaces
        # in the plaintext relative to the most frequent character group

        most_frequent = sorted(hist.items(), key=lambda p: p[1], reverse=True)[0]

        if ' ' in hist and hist[' '] / most_frequent[1] > best_score:
            best_score = hist[' '] / most_frequent[1]
            p = utf8_msg
            key = cand

    return p, best_score, key.to_bytes()

if __name__ == '__main__':
    keysize = 16
    key = urandom(keysize)
    nonce = bytes([0]*8)

    with open('20.txt', 'r') as file:
        pt_lines = [b64decode(line.strip()) for line in file]

    ct_lines = [aes_ctr_encrypt(line, nonce, key) for line in pt_lines]

    # Truncate ciphertexts to the length of the shortest ciphertext
    truncate_len = len(min(ct_lines, key=len))
    truncated_cts = [line[:truncate_len] for line in ct_lines]

    # Concatenate truncated ciphertexts
    concatenated_cts = b''.join(truncated_cts)

    # Create truncate_len number of blocks
    # Each block is essentially encrypted using a single byte xor since the ctr and nonce are the same
    blocks = [concatenated_cts[i::truncate_len] for i in range(truncate_len)]

    # Get the stream used to xor the plaintext
    stream = b''.join(decodeSingleByteXOR(block)[2] for block in blocks)

    for ct in truncated_cts:
        print(aes_ctr_stream_decrypt(ct, stream).decode('utf-8'))

