# An ECB/CBC detection oracle
# https://www.cryptopals.com/sets/2/challenges/11
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from challenge_10 import AES_CBC_Encrypt
from challenge_9 import pkcs7_pad
from os import urandom
from random import randint

def encryption_oracle(data):
    pt = urandom(randint(5, 10)) + data + urandom(randint(5, 10))
    key = urandom(16)

    if randint(0, 1):
        print('Oracle is using ECB')
        padded_pt = pkcs7_pad(pt, 16)
        cipher = Cipher(algorithms.AES(key), modes.ECB())
        encryptor = cipher.encryptor()
        return encryptor.update(padded_pt) + encryptor.finalize()
    else:
        print('Oracle is using CBC')
        return AES_CBC_Encrypt(pt, urandom(16), key)

# test_data is 6 bytes long
# between 10 and 20 bytes will be randomly added before encyption
# this will mean that the plaintext after padding will be 32 bytes
# the output of ECB will not add an iv so the ciphertext will remain 32 bytes
# the output of CBC will add an extra iv so the ciphertext will be longer than 32 bytes
def detect_ECB_CBC(oracle):
    test_data = b'helloo'
    if len(encryption_oracle(test_data)) == 32:
        print('Detected ECB mode')
    else:
        print('Detected CBC mode')

if __name__ == '__main__':
    print('Encryption oracle ciphertext for input "hello world"')
    print(b'Ciphertext: ' + encryption_oracle(b'hello world'))

    detect_ECB_CBC(encryption_oracle)
