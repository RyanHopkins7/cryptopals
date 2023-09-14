# Detect single-character XOR
# https://www.cryptopals.com/sets/1/challenges/4

from challenge_3 import decodeSingleByteXOR


if __name__ == '__main__':
    words_file = open('words.txt')
    words = [l.lower().strip() for l in words_file.readlines()]

    hex_strings_file = open('4.txt')
    hex_strings = list(int(l.lower().strip(), 16) for l in hex_strings_file.readlines())

    # Iterate through all hex strings, run decodeSingleByteXOR,
    # and find the decoded string which contains >1 word
    for h in hex_strings:
        try:
            out = decodeSingleByteXOR(h, words)
            if out[1] > 1:
                print(out[0])
        except UnicodeDecodeError:
            pass
