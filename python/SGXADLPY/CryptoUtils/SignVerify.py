#from Crypto.Hash import SHA256
#from Crypto.PublicKey import ECC
#from Crypto.Signature import DSS

from ecdsa import SigningKey,NIST256p,VerifyingKey
from ecdsa.util import sigencode_string, sigdecode_string
from hashlib import sha256

class ECCSigner(object):
    
    # sk_file = None
    # priv_key = None
    # signer = None

    def __init__(self,SK_file):
        if SK_file is None:
            raise RuntimeError("SK_file for signing cannot be null")
        self.sk_file = SK_file
    
    def LoadSigKey(self):
        #with open(self.sk_file,'rt') as f:
        with open(self.sk_file,'rb') as f:
            #self.priv_key = ECC.import_key(f.read())
            self.signer = SigningKey.from_string(f.read(),curve=NIST256p,hashfunc=sha256)

    def SignMsg(self,message):
        #msg_sha256 = SHA256.new(message)
        #signature = self.signer.sign(msg_sha256)
        signature = self.signer.sign(message,hashfunc=sha256,sigencode=sigencode_string)
        return signature


class ECCVerifier(object):

    def __init__(self,PK_file):
        if PK_file is None:
            raise RuntimeError("PK_file for signing cannot be null")
        self.pk_file = PK_file

    def LoadSigKey(self):
        #with open(self.pk_file,'rt') as f:
        with open(self.pk_file,'rb') as f:
            #self.pub_key = ECC.import_key(f.read())
            self.verifier = VerifyingKey.from_string(f.read(), curve=NIST256p,hashfunc=sha256)
        #self.verifier = DSS.new(self.pub_key,'fips-186-3')
    
    def VerifyMsg(self,message,signature):
        #msg_sha256 = SHA256.new(message)
        #self.verifier = DSS.new(self.pk_key, 'fips-186-3')
        # try:
        #     #self.verifier.verify(msg_sha256,signature)
        #     return True
        # except ValueError:
        #     print("Could not verify message!")

        self.verifier.verify(signature,message,hashfunc=sha256,sigdecode=sigdecode_string)

if __name__ == "__main__":
    pass

