# Detect single-character XOR
# https://www.cryptopals.com/sets/1/challenges/4

from challenge_3 import decodeSingleByteXOR


if __name__ == '__main__':
    hex_strings_file = open('4.txt')
    hex_strings = [int(l.lower().strip(), 16) for l in hex_strings_file.readlines()]
    hex_strings_file.close()

    pt = ''
    best_score = 0
    key = None

    # Iterate through all hex strings, run decodeSingleByteXOR,
    # and find the decoded string which scores highest
    for h in hex_strings:
        res = decodeSingleByteXOR(h)
        if res[1] > best_score:
            pt, best_score, key = res

    print(pt, best_score, key)
