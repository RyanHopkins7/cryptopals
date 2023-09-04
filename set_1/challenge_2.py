# Fixed XOR
# https://www.cryptopals.com/sets/1/challenges/2

# Pretty straightforward again: take bitwise xor and return hex encoding
def xor(a, b):
    return hex(a ^ b)

print(xor(0x1c0111001f010100061a024b53535009181c, 0x686974207468652062756c6c277320657965))
