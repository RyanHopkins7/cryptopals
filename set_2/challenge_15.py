# PKCS#7 padding validation
# https://www.cryptopals.com/sets/2/challenges/15

def strip_padding(data):
    pad_len = data[-1]
    for i in range(len(data)-1, len(data)-1-pad_len, -1):
        if data[i] != pad_len:
            raise Exception('PKCS7 padding invalid')
    return data[:-pad_len]

if __name__ == '__main__':
    print(strip_padding(b'ICE ICE BABY\x04\x04\x04\x04'))
    print(strip_padding(b'ICE ICE BABY\x05\x05\x05\x05'))
    print(strip_padding(b'ICE ICE BABY\x01\x02\x03\x04'))
