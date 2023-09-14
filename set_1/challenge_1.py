# Convert hex to base64
# https://www.cryptopals.com/sets/1/challenges/1

import base64

# This function is pretty straightforward: it just base64 encodes hex data
def hex2b64(hex):
    # https://docs.python.org/3/library/stdtypes.html?highlight=to_bytes#int.to_bytes
    b2 = hex.to_bytes((hex.bit_length() + 7) // 8, byteorder='big')
    return base64.b64encode(b2)


if __name__ == '__main__':
    print(hex2b64(0x49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d))
