# Byte-at-a-time ECB decryption (Harder)
# https://www.cryptopals.com/sets/2/challenges/14
from challenge_12 import AES_ECB_Encrypt
from base64 import b64decode
from os import urandom

oracle = lambda pt, k: AES_ECB_Encrypt(urandom(urandom(1)[0]) + pt, k)

if __name__ == '__main__':
    key = urandom(16)
    unknown_string = b64decode('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')
    
    # This is more difficult than challenge 12 because we can't reliably craft an input 
    # that's exactly one byte short of the block size.
    # Assume we know that ECB is being used and block size is 16 already
    block_size = 16
    my_str = b'A' * (block_size-1) 

    ct_lookup = {}
    while len(ct_lookup) < 255:
        for c in range(255):
            msg = (my_str + c.to_bytes(1, 'big')) * 10
            ct = oracle(msg, key)
            blocks = [ct[i:i+block_size] for i in range(0, len(ct), 16)]

            # There will be exactly 10 blocks of chosen ciphertext of my_str + chr
            # only if my_str + chr is aligned to take up exactly a single block length.
            # This is because otherwise, some block(s) will be split by the random data.
            if blocks.count(blocks[-2]) == 10:
                ct_lookup[blocks[-2]] = chr(c)
    
    # Once we have the ct_lookup table, we can simply search the blocks in the 
    # ciphertext for corresponding characters in the plaintext.
    known_string = ''
    while len(unknown_string) > 0:
        ct = oracle(my_str + unknown_string, key)
        for i in range(0, len(ct), 16):
            if ct[i:i+16] in ct_lookup:
                known_string += ct_lookup[ct[i:i+16]]
                unknown_string = unknown_string[1:]
                break
    
    print("Decoded plaintext:")
    print(known_string)
