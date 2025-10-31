# Implement the MT19937 Mersenne Twister RNG
# https://cryptopals.com/sets/3/challenges/21

w = 32
n = 624
m = 397
r = 31
a = 0x9908b0df
f = 0x1812433253
u = 11
s = 7
t = 15
l = 18
b = 0x9d2c5680
c = 0xefc60000
UMASK = 0xffffffff << r
LMASK = 0xffffffff >> (w-r)

# Source: https://en.wikipedia.org/wiki/Mersenne_Twister
class RNG:
    def __init__(self, seed):
        # suggested initial seed = 0x19650218
        self.state_array = [seed]

        for i in range(1, n):
            seed = f * (seed ^ (seed >> (w-2))) + i
            self.state_array.append(seed)

        self.state_index = 0

    def rand(self):
        # point to current state location
        # 0 <= state_index <= n-1   always
        k = self.state_index

        j = k - (n-1) # point to state n-1 iterations before
        if (j < 0):   # modulo n circular indexing
            j += n

        x = (self.state_array[k] & UMASK) | (self.state_array[j] & LMASK)

        xA = x >> 1
        if (x & 0x00000001):
            xA ^= a

        j = k - (n-m) # point to state n-m iterations before
        if (j < 0):   # modulo n circular indexing
            j += n

        x = self.state_array[j] ^ xA # compute next value in the state
        self.state_array[k] = x      # update new state value
        k += 1

        if (k >= n):  # modulo n circular indexing
            k = 0
        self.state_index = k

        y = x ^ (x >> u)             # tempering 
        y = y ^ ((y << s) & b)
        y = y ^ ((y << t) & c)
        z = y ^ (y >> l)

        return z

if __name__ == '__main__':
    seed = 0x19650218
    rng = RNG(seed)
    for _ in range(10):
        print(rng.rand() & 0xffffffffffffffff)
