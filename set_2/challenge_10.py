# Implement CBC Mode
# https://www.cryptopals.com/sets/2/challenges/10
from challenge_9 import pkcs7_pad
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from functools import reduce
import base64

def AES_CBC_Encrypt(data, iv, key):
    padded_data = pkcs7_pad(data, 16)
    blocks = [iv] + [padded_data[i:i+16] for i in range(0, len(padded_data), 16)]
    cipher = Cipher(algorithms.AES(key), modes.ECB())

    for i in range(1, len(blocks)):
        block_iv = blocks[i-1]
        block_pt = blocks[i]
        pt_xor_iv = bytes([block_pt[j] ^ block_iv[j] for j in range(16)])

        encryptor = cipher.encryptor()
        block_ct = encryptor.update(pt_xor_iv) + encryptor.finalize()

        blocks[i] = block_ct

    return reduce(lambda x,y: x+y, blocks)

def AES_CBC_Decrypt(data, key):
    blocks = [data[i:i+16] for i in range(0, len(data), 16)]
    cipher = Cipher(algorithms.AES(key), modes.ECB())

    for i in range(1, len(blocks)):
        block_iv = blocks[i-1]
        block_ct = blocks[i]

        decryptor = cipher.decryptor()
        pt_xor_iv = decryptor.update(block_ct) + decryptor.finalize()
        block_pt = bytes([pt_xor_iv[j] ^ block_iv[j] for j in range(16)])

        blocks[i-1] = block_pt

    padded_pt = reduce(lambda x,y: x+y, blocks[:-1])
    return padded_pt[:-padded_pt[-1]]


if __name__ == '__main__':
    test_msg = b'helloooooooo world!!!'
    test_iv = b'\x00' * 16
    test_key = b'YELLOW SUBMARINE'

    test_ct = AES_CBC_Encrypt(test_msg, test_iv, test_key)
    print('Test ciphertext: ' + str(test_ct))

    test_pt = AES_CBC_Decrypt(test_ct, test_key)
    print('Test plaintext: ' + test_pt.decode('utf-8'))

    file = open('10.txt')
    b64_ct = file.read().strip()
    file.close()

    file_ct = base64.b64decode(b64_ct)
    file_pt = AES_CBC_Decrypt(test_iv + file_ct, test_key)

    print('File plaintext:')
    print(file_pt.decode('utf-8'))
