# AES in ECB mode
# https://cryptopals.com/sets/1/challenges/7
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64

# Decrypt AES-ECB encrypted data with the key given
if __name__ == '__main__':
    file = open('7.txt')
    b64_ct = file.read().strip()
    file.close()

    ct = base64.b64decode(b64_ct)
    key = b'YELLOW SUBMARINE'
    cipher = Cipher(algorithms.AES(key), modes.ECB())

    decryptor = cipher.decryptor()
    print((decryptor.update(ct) + decryptor.finalize()).decode('utf-8'))

