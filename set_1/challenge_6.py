# https://www.cryptopals.com/sets/1/challenges/6
# Break repeating-key XOR

from base64 import b64decode
from challenge_3 import decodeSingleByteXOR

# Hamming algorithm from Peter Wegner
# https://dl.acm.org/doi/pdf/10.1145/367236.367286
def hamming_dist(b1, b2):
    i1 = int.from_bytes(b1)
    i2 = int.from_bytes(b2)
    dist = 0

    # Val contains all differing bytes between s1_int and s2_int
    val = i1 ^ i2
    while val > 0:
        # Here, we count all the differing bytes
        val &= val-1
        dist += 1

    return dist

def predict_keysize(bytes, min_keysize, max_keysize):
    predicted_keysize = min_keysize
    min_avg_dist = float('inf')

    # Loop through all possible candidate key sizes
    for cand in range(min_keysize, max_keysize+1):
        avg_dist = 0
        iter = range(0, len(bytes), cand*2)

        # Get hamming distance for alternating blocks of candidate key size
        for i in iter:
            avg_dist += hamming_dist(bytes[i:i+cand], bytes[i+cand:i+2*cand])

        # Normalize average hamming distance
        avg_dist /= len(iter)
        avg_dist /= cand

        # And we select the key size which produces the lowest normalized average hamming distance
        if avg_dist < min_avg_dist:
            min_avg_dist = avg_dist
            predicted_keysize = cand

    return predicted_keysize


if __name__ == '__main__':
    s1_bytes = b'this is a test'
    s2_bytes = b'wokka wokka!!!'
    hamming_test = hamming_dist(s1_bytes, s2_bytes)
    print(f"Hamming dist between 'this is a test' and 'wokka wokka!!!': {hamming_test}")

    enc_file = open('6.txt')
    enc_data = b64decode(enc_file.read().strip())
    enc_file.close()

    predicted_keysize = predict_keysize(enc_data, 2, 40)
    print(f"Predicted keysize of encrypted data: {predicted_keysize}")

    # We split enc_data into key_size blocks
    # Each block is encrypted with a single byte XOR
    # So we can use our decodeSingleByteXOR function here!
    blocks = [enc_data[i::predicted_keysize] for i in range(predicted_keysize)]
    key = ''.join(decodeSingleByteXOR(int.from_bytes(block))[2] for block in blocks)
    print(f'Decryption key: {key}')

    # Decrypt the data with the key
    decrypted_data = ''.join(chr(b ^ ord(key[i % predicted_keysize])) for i, b in enumerate(enc_data))
    print('Decypted data:\n')
    print(decrypted_data)

