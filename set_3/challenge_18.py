# Implement CTR, the stream cipher mode
# https://www.cryptopals.com/sets/3/challenges/18
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import os

def aes_ctr_stream(nonce, key, ctr):
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(nonce + ctr) + encryptor.finalize()

def aes_ctr_encrypt(pt, nonce, key):
    ct = bytearray()
    ctr = 0
    while len(ct) < len(pt):
        ctr_bytes = ctr.to_bytes(8, 'little')
        stream = aes_ctr_stream(nonce, key, ctr_bytes)
        for i, b in enumerate(stream):
            ct_idx = ctr*16+i
            if ct_idx < len(pt):
                ct.append(b ^ pt[ct_idx])
            else:
                break
        ctr += 1
    return ct

def aes_ctr_decrypt(ct, nonce, key):
    pt = bytearray()
    ctr = 0
    while len(pt) < len(ct):
        ctr_bytes = ctr.to_bytes(8, 'little')
        stream = aes_ctr_stream(nonce, key, ctr_bytes)
        for i, b in enumerate(stream):
            pt_idx = ctr*16+i
            if pt_idx < len(ct):
                pt.append(b ^ ct[pt_idx])
            else:
                break
        ctr += 1
    return pt

if __name__ == '__main__':
    key = b'YELLOW SUBMARINE'
    nonce = bytes([0]*8)
    ct = base64.b64decode('L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==')
    print('ciphertext 1:')
    print(ct)
    pt = aes_ctr_decrypt(ct, nonce, key)
    print('plaintext 1:')
    print(pt)

    pt2 = b'hello world'
    key2 = os.urandom(16)
    nonce2 = os.urandom(8)
    ct2 = aes_ctr_encrypt(pt2, nonce2, key2)
    print('ciphertext 2:')
    print(ct2)
    pt2 = aes_ctr_decrypt(ct2, nonce2, key2)
    print('plaintext 2:')
    print(pt2)
