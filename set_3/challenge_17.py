# The CBC padding oracle
# https://www.cryptopals.com/sets/3/challenges/17
# also see https://research.nccgroup.com/2021/02/17/cryptopals-exploiting-cbc-padding-oracles/
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from os import urandom
import random
import base64

# block size of 16 bytes
class Oracle:
    def __init__(self):
        self.key = urandom(16)

    def encrypt_random(self):
        strings = [
            'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
            'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
            'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
            'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
            'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
            'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
            'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
            'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
            'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
            'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93'
        ]

        encoded_pt = random.choice(strings).encode('ascii')
        pt = base64.b64decode(encoded_pt)

        pad_len = 16 - (len(pt) % 16)
        padded_pt = pt + bytearray([pad_len] * pad_len)

        if pad_len == 0:
            padded_pt = pt + bytearray([16] * 16)

        iv = urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ct = encryptor.update(padded_pt) + encryptor.finalize()

        return ct, iv

    # return true or false depending if the padding is valid
    def check_padding(self, ct, iv):
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_pt = decryptor.update(ct) + decryptor.finalize()
        padding_byte = padded_pt[len(padded_pt)-1]

        if len(padded_pt) % 16 != 0:
            return False

        if padding_byte <= 0 or padding_byte > 16:
            return False

        for i in range(len(padded_pt)-padding_byte, len(padded_pt)):
            if i < 0 or i > len(padded_pt) or padded_pt[i] != padding_byte:
                return False

        return True


if __name__ == '__main__':
    o = Oracle()
    ct, iv = o.encrypt_random()

    pt = bytearray()
    ct = iv + ct

    for block_i in range(len(ct), 16, -16):
        block_iv = ct[block_i-32:block_i-16]
        block_ct = ct[block_i-16:block_i]

        # zeroing iv sets the plaintext bytes to zero
        zeroing_iv = bytearray([0] * 16)

        for pad_i in range(15, -1, -1):
            # set candidate iv to produce the correct padding
            candidate_iv = bytearray(
                [0] * (pad_i+1)
            ) + bytearray(
                [b ^ (16-pad_i) for b in zeroing_iv[pad_i+1:]]
            )

            for candidate in range(0, 256):
                candidate_iv[pad_i] = candidate

                if o.check_padding(block_ct, candidate_iv):
                    # check for false positive
                    if pad_i == 15:
                        candidate_iv[-2] ^= 0xff
                    if o.check_padding(block_ct, candidate_iv):
                        zeroing_iv[pad_i] = candidate_iv[pad_i] ^ (16 - pad_i)
                        break

        pt = bytearray([b_iv ^ b_ziv for b_iv, b_ziv in zip(block_iv, zeroing_iv)]) + pt

    print('plaintext:')
    print(pt[:-pt[-1]].decode('ascii'))
