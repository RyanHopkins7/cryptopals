# CBC bitflipping attacks
# https://www.cryptopals.com/sets/2/challenges/16
from challenge_10 import AES_CBC_Encrypt, AES_CBC_Decrypt
from os import urandom

def encrypt_comments(user_data, key):
    clean_user_data = user_data.replace(';', '%3B').replace('=', '%3D')
    pt = 'comment1=cooking%20MCs;userdata=' + clean_user_data + ';comment2=%20like%20a%20pound%20of%20bacon'
    return AES_CBC_Encrypt(pt.encode('utf-8'), urandom(16), key)

def is_admin(ct, key):
    pt = AES_CBC_Decrypt(ct, key)
    return b';admin=true;' in pt

if __name__ == '__main__':
    key = urandom(16)
    # Add two blocks of zero bytes
    ct = encrypt_comments((b'\x00'*32).decode('utf-8'), key)
    modified_ct = bytearray(ct)

    # Modify the first block of ciphertext of the zero bytes so that
    # the second block will decrypt to five zero bytes + ;admin=true
    # after being XORed with the previous block of ciphertext
    for i in range(53, 64):
        modified_ct[i] ^= b';admin=true'[i-53]

    print("Modified ciphertext contains ;admin=true;:")
    print(is_admin(modified_ct, key))
