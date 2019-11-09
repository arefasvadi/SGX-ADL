from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class AEncDec(object):
    
    def __init__(self, key_f):
        self.key_file = key_f
    
    def LoadKey(self):
        with open(self.key_file,'rb') as f:
            self.key = f.read()

    def Encrypt(self,bytes,iv=None,aad=None):
        if bytes is None:
            raise ValueError("bytes is None")
        pass
        if iv is None:
            iv = get_random_bytes(12)

        cipher = AES.new(self.key, AES.MODE_GCM,nonce=iv,mac_len=16)
        if aad is not None:
            cipher.update(aad)
        
        cipher, tag = cipher.encrypt_and_digest(bytes)
        
        return (cipher,tag,iv,aad)

    def Decrypt(self,enc_bytes,iv=None,aad=None):
        if enc_bytes is None or iv is None:
            raise ValueError("enc_bytes or iv is None")
        cipher = AES.new(self.key, AES.MODE_GCM,nonce=iv,mac_len=16)
        if aad is not None:
            cipher.update(aad)
        plaintext = cipher.decrypt_and_verify(enc_bytes,tag)

        return plaintext

if __name__ == "__main__":
    pass