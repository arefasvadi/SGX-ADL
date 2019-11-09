#from Crypto.Hash import SHA256
#from Crypto.PublicKey import ECC

from ecdsa import SigningKey,NIST256p,VerifyingKey
from ecdsa.util import sigencode_string, sigdecode_string
from hashlib import sha256
import sys

def gen_ecc_kp(PK_file,SK_file) :
    if PK_file is None or SK_file is None:
        raise RuntimeError("PK_file or SK_file is empty")

    #sk_key = ECC.generate(curve='secp256r1')
    #pk_key = sk_key.public_key()
    sk_key = SigningKey.generate(curve=NIST256p,hashfunc=sha256)
    pk_key = sk_key.verifying_key

    temp_msg = b'I am a message'
    signed_bytes = sk_key.sign(temp_msg,hashfunc=sha256,sigencode=sigencode_string)
    if not pk_key.verify(signed_bytes,temp_msg,hashfunc=sha256,sigdecode=sigdecode_string) :
        raise RuntimeError('msg and sig did not match!\n')
    #with open(PK_file,'wt') as f:
    with open(PK_file,'wb') as f:
        #f.write(pk_key.export_key(format="PEM",compress=False))
        f.write(pk_key.to_string())
    #with open(SK_file,'wt') as f:
    with open(SK_file,'wb') as f:
        #f.write(sk_key.export_key(format="PEM",passphrase=None,use_pkcs8=False,compress=False))
        f.write(sk_key.to_string())
    test_ecc_kp_keys(sys.argv[1],sys.argv[2])
    print('finished checking Sanity of ECC KeyPairs')

def test_ecc_kp_keys(PK_file,SK_file):
    #sk_key = SigningKey.generate(curve=SECP256k1)
    #pk_key = sk.verifying_key
    
    if PK_file is None or SK_file is None:
        raise RuntimeError("PK_file or SK_file is empty")
    #with open(PK_file,'rt') as f:
    with open(PK_file,'rb') as f:
        #pk_key = ECC.import_key(f.read())    
        pk_key = VerifyingKey.from_string(f.read(), curve=NIST256p,hashfunc=sha256)
    #with open(SK_file,'rt') as f:
    with open(SK_file,'rb') as f:
        #sk_key = ECC.import_key(f.read())
        sk_key = SigningKey.from_string(f.read(),curve=NIST256p,hashfunc=sha256)
    temp_msg = b'I am a message'
    sig_bytes = sk_key.sign(temp_msg,hashfunc=sha256,sigencode=sigencode_string)
    if not pk_key.verify(sig_bytes,temp_msg,hashfunc=sha256,sigdecode=sigdecode_string) :
        raise RuntimeError('read keys from file | msg and sig did not match!\n')

if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise RuntimeError("this script should be run with two files. PK_file, SK_file")
    
    gen_ecc_kp(sys.argv[1],sys.argv[2])
    print('finished generating ECC KeyPairs')
        

# openssl ecparam -name prime256v1 -genkey -noout -out client_sig_sk.pem
# openssl ec -in client_sig_sk.pem -pubout -out client_sig_pk.pem