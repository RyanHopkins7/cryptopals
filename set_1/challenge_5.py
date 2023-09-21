# https://www.cryptopals.com/sets/1/challenges/5
# Implement repeating-key XOR

def encRepeatingKeyXOR(pt, key):
    enc_pt = [ord(pt[i]) ^ ord(key[i % len(key)]) for i in range(len(pt))]
    print("".join('{:02x}'.format(c) for c in enc_pt))


if __name__ == '__main__':
    pt = """Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"""
    encRepeatingKeyXOR(pt, "ICE")
