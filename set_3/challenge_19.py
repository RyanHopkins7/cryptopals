# Break fixed-nonce CTR mode using substitutions
# https://cryptopals.com/sets/3/challenges/19

from challenge_18 import aes_ctr_encrypt
from os import urandom
from base64 import b64decode

if __name__ == '__main__':
    key = urandom(16)
    nonce = bytes([0]*8)

    with open('19.txt', 'r') as file:
        pt_lines = [b64decode(line.strip()) for line in file]

    ct_lines = [aes_ctr_encrypt(line, nonce, key) for line in pt_lines]

    # pt 0: 'I have met them at close of d'
    # pt 1: 'Coming with '
    # pt 2: 'From counter or desk among gr'
    # pt 3: 'Eighteenth-century houses'
    # pt 4: 'I have passed with a nod of the '
    # pt 5: 'Or polite meaningless word'
    # pt 6: 'Or have lingered awhile and said'
    # pt 8: 'And thought before I had done'
    # pt 12: 'Being certain that they and I'
    # pt 13: 'But lived where motley is wor'
    # pt 27: 'He might have won fame in the '
    # pt 37: 'He, too, has been changed in his turn'

    guessed_pt = b'He, too, has been changed in his turn'
    guessed_pt_line = 37
    guessed_key = bytearray([0] * len(guessed_pt))

    for i in range(len(guessed_key)):
        guessed_key[i] = ct_lines[guessed_pt_line][i] ^ guessed_pt[i]

    print("decoded ciphertext: \n")
    for ct in ct_lines:
        pt = bytearray([0] * len(guessed_key))
        for i in range(min(len(guessed_key), len(ct))):
            pt[i] = ct[i] ^ guessed_key[i]
        print(pt.decode('utf-8'))


    # guessed_pt = b'That '
    # Ciphertext line:  20
    # Guessed key:  bytearray(b'\x83t{u<')
    # Guessed next plaintext:  bytearray(b'Then ')

    # guessed_pt = b'Then '
    # Ciphertext line:  20
    # Guessed key:  bytearray(b'y\x8f\xdf9\xeb')
    # Guessed next plaintext:  bytearray(b'That ')

    # for i, ct in enumerate(ct_lines[:-1]):
    #     print('Ciphertext line: ', i)

    #     guessed_key = bytearray([0] * len(guessed_pt))
    #     for j in range(len(guessed_pt)):
    #         guessed_key[j] = ct[j] ^ guessed_pt[j]

    #     print('Guessed key: ', guessed_key)

    #     next_pt = bytearray([0] * len(guessed_pt))
    #     for j in range(len(guessed_key)):
    #         next_pt[j] = ct_lines[i+1][j] ^ guessed_key[j]

    #     print('Guessed next plaintext: ', next_pt)

    print("\nactual plaintext lines: \n")
    for line in pt_lines:
        print(line.decode('utf-8'))

