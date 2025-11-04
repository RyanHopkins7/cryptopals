# https://cryptopals.com/sets/3/challenges/23
# Clone an MT19937 RNG from its output

u = 11
s = 7
t = 15
l = 18
b = 0x9d2c5680
c = 0xefc60000

def temper(x):
    y = x ^ (x >> u)
    y = y ^ ((y << s) & b)
    y = y ^ ((y << t) & c)
    print(bin(y))
    z = y ^ (y >> l)
    return z

def unrightshift(z, shift):
    # Source: https://stackoverflow.com/questions/62409600/how-to-reverse-xor-shift-operations
    n = 0
    while shift * 2**n <= z.bit_length():
        z = z ^ (z >> (shift * 2**n))
        n += 1
    return z

def unleftshift(z, shift, bitmask):
    # TODO
    pass

def untemper(z):
    # Reverse the "tempering" operations of MT19937
    z = unrightshift(z, l)
    print(bin(z))
    # y = unleftshift(z, t, c)
    # y = unleftshift(y, s, b)
    # x = unrightshift(y, u)
    # return x

if __name__ == '__main__':
    tempered = temper(124567890124567890124567890)
    untemper(tempered)
