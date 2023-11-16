# ECB cut-and-paste
# https://www.cryptopals.com/sets/2/challenges/13
from challenge_12 import AES_ECB_Encrypt
from challenge_9 import pkcs7_pad
from os import urandom
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def parse_profile(profile):
    return {s[:s.index('=')]: s[s.index('=')+1:] for s in profile.split('&')}

def encrypt_profile(profile, key):
    padded_profile = pkcs7_pad(bytes(profile, 'utf-8'), block_size=16)
    return b64encode(AES_ECB_Encrypt(padded_profile, key)).decode('utf-8')

def profile_for(email, key=b''):
    safe_email = email.replace('=', '').replace('&', '')
    profile = f'email={safe_email}&uid=10&role=user'
    return encrypt_profile(profile, key) if key != b'' else profile

def decrypt_parse_profile(profile_ct, key):
    ct = b64decode(profile_ct)
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    padded_pt = decryptor.update(ct) + decryptor.finalize()
    pt = padded_pt[:-padded_pt[-1]]
    return pt.decode('utf-8')


if __name__ == '__main__':
    key = urandom(16)
    print('Parsed profile: ' + str(parse_profile('foo=bar&baz=qux&zap=zazzle')))

    p = profile_for('foo@bar.com')
    print('Profile for foo@bar.com: ' + p)

    p_ct = encrypt_profile(p, key)
    print('Encrypted profile: ' + p_ct)

    print('Decrypted profile: ' + decrypt_parse_profile(p_ct, key))

    # We want to make an admin profile using only profile_for
    # The following profile is 37 characters long resulting in only "user" being placed in the last block
    # email=aaaaa@test.com&uid=10&role=user
    # We slice the first two blocks and then try to find the ciphertext to make the last block "admin"
    admin_p_blocks = b64decode(profile_for('aaaa@test.com', key))[:32]

    # We can find the correct last block of ciphertext by using the following email
    # The block we want should be the second block -- admin + correct pkcs7 padding
    evil_email = (b'AAAAAAAAAAadmin' + bytes([11]*11) + b'@test.com').decode('utf-8')
    evil_p_ct = b64decode(profile_for(evil_email, key))
    
    admin_p_blocks += evil_p_ct[16:32]
    admin_token = b64encode(admin_p_blocks)

    decrypted_admin_profile = decrypt_parse_profile(admin_token, key)
    print('Forged admin token: ' + str(parse_profile(decrypted_admin_profile)))
