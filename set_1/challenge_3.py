# Single-byte XOR cipher
# https://www.cryptopals.com/sets/1/challenges/3

# Iterate over all possible key values and select the one which scores highest
def decodeSingleByteXOR(hex):
    p = ''
    best_score = 0
    key = None

    for cand in range(0, 128):
        msg_bytes = bytes(b ^ cand for b in hex.to_bytes((hex.bit_length() + 7) // 8, 'big'))
        utf8_msg = msg_bytes.decode('utf-8', errors='replace').lower()
        
        hist = {}
        for c in utf8_msg:
            # group all chars which are not a space or letter together
            if ord(c) != 0x20 and (ord(c) < 0x61 or ord(c) > 0x7a):
                c = 'nonalpha'

            if c in hist:
                hist[c] += 1
            else:
                hist[c] = 1

        # In English text, space is the most common character
        # Source: https://en.wikipedia.org/wiki/Letter_frequency
        # So, here we're looking for the key which produces the most spaces
        # in the plaintext relative to the most frequent character group

        most_frequent = sorted(hist.items(), key=lambda p: p[1], reverse=True)[0]
        if ' ' in hist and hist[' '] / most_frequent[1] > best_score:
            best_score = hist[' '] / most_frequent[1]
            p = utf8_msg
            key = cand

    return p, best_score, chr(key)


if __name__ == '__main__':
    c = 0x1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
    print(decodeSingleByteXOR(c))
