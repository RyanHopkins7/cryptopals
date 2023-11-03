# Byte-at-a-time ECB decryption (Simple)
# https://www.cryptopals.com/sets/2/challenges/12
from os import urandom
from challenge_9 import pkcs7_pad
from challenge_11 import detect_ECB_CBC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import b64decode

def AES_ECB_Encrypt(pt, k):
    padded_pt = pkcs7_pad(pt, 16)
    cipher = Cipher(algorithms.AES(k), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(padded_pt) + encryptor.finalize()


if __name__ == '__main__':
    key = urandom(16)
    unknown_string = b64decode('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')

    # Step 1: Detect block size
    ct_len = len(AES_ECB_Encrypt(b'A', key))
    for i in range(1, 129):
        new_ct_len = len(AES_ECB_Encrypt(b'A'*i, key))
        if new_ct_len != ct_len:
            block_size = i
            break
        
    # Step 2: Detect that the function is using ECB
    if detect_ECB_CBC(AES_ECB_Encrypt, key, b'A', 16) == 'ECB':
        # Step 3: Craft an input exactly one byte short of the block size
        my_str = b'A' * (block_size-1) 
        
        # Step 4: Make a dictionary of every possible last byte
        ct_lookup = {
            AES_ECB_Encrypt(
                my_str + c.to_bytes(1, 'big'),
                key
            )[:block_size]: my_str + c.to_bytes(1, 'big') for c in range(256)
        }

        # Step 5: Byte-by-byte decipher the unknown string using the lookup dictionary
        print("Decoded plaintext:")
        known_string = ''
        while len(unknown_string) > 0:
            ct = AES_ECB_Encrypt(my_str + unknown_string, key)
            known_string += chr(ct_lookup[ct[:block_size]][-1])
            unknown_string = unknown_string[1:]

        print(known_string)

