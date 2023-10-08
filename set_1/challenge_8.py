# https://cryptopals.com/sets/1/challenges/8
# Detect AES in ECB mode

import base64

if __name__ == '__main__':
    file = open('8.txt')
    cts = [base64.b64decode(l.strip()) for l in file.readlines()]
    file.close()

    for i, ct in enumerate(cts):
        # The logic here is that in AES-ECB, the same 16 byte plaintext block
        # will always encrypt to the same 16 byte ciphertext.
        # Therefore, we're looking for the ciphertext which contains repeated blocks
        blocks = [ct[i:i+16] for i in range(0, len(cts), 16)]
        if len(blocks) != len(set(blocks)):
            print(f'The ciphertext on line {i+1} is encrypted using AES-ECB')
