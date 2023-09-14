# Single-byte XOR cipher
# https://www.cryptopals.com/sets/1/challenges/3

# The method I'm using to 'score' English plaintext is by the 
# number of english words which can be deciphered from it.
# The plaintext with the highest number of words is selected.
def decodeSingleByteXOR(hex, words_set):
    most_words = 0
    p = ''

    for k in range(0, 128):
        msg_bytes = bytes(b ^ k for b in hex.to_bytes((hex.bit_length() + 7) // 8, 'big'))
        msg = msg_bytes.decode('utf-8')

        msg_word_set = set(msg.lower().split(' '))
        n_words = len(set.intersection(msg_word_set, words_set))

        if n_words > most_words:
            most_words = n_words
            p = msg

    return p, most_words


if __name__ == '__main__':
    # words.txt from https://github.com/dwyl/english-words
    words_file = open('words.txt')
    words = [l.lower().strip() for l in words_file.readlines()]
    c = 0x1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736

    print(decodeSingleByteXOR(c, set(words))[1])
