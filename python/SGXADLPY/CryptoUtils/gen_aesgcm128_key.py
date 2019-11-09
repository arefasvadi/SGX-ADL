from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def gen_aesgcm128_key(key_file):
    if key_file is None:
        raise ValueError("key_file cannot be null")
    key = get_random_bytes(16)
    with open(key_file,'wb') as f:
        f.write(key)
    print('finished generating the aesgcm128 key')

if __name__ == "__main__":
    pass