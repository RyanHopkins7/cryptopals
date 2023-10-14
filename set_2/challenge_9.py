# Implement PKCS#7 padding
# https://www.cryptopals.com/sets/2/challenges/9

def pkcs7_pad(unpadded, block_size):
    pad_len = block_size - (len(unpadded) % block_size)

    if pad_len == 0:
        return unpadded + bytearray([block_size] * block_size)
    
    return unpadded + bytearray([pad_len] * pad_len)

if __name__ == '__main__':
    print(pkcs7_pad(b'YELLOW SUBMARINE', 20))
