from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from pprint import pprint
import os
import sys
import numpy as np
import pandas as pd

C_W_DIR = os.getcwd()
SC_DIR = os.path.dirname(os.path.realpath(__file__))

# This is where you put normal and tumor text file paths
NORMAL_FILE_TEXT = './sgx_track_data/GSE25066-Normal-50-sgx.txt'
TUMOR_FILE_TEXT = './sgx_track_data/GSE25066-Tumor-50-sgx.txt'

def main():
    normal_data = pd.read_csv(NORMAL_FILE_TEXT,sep='\t',header=0).transpose()
    tumor_data = pd.read_csv(TUMOR_FILE_TEXT,sep='\t',header=0).transpose()

    norm_vals = normal_data.iloc[1:,].values.astype(np.float32)
    norm_names = normal_data.iloc[1:].index.tolist()

    tumor_vals = tumor_data.iloc[1:,].values.astype(np.float32)
    tumor_names = tumor_data.iloc[1:].index.tolist()
    
    with open('./records/predict.list','w') as test_f, \
        open('./records_encrypted/predict_encrypted.list','w') as enc_test_f:

        for cnt, fname in enumerate(tumor_names):
            with open('./records/tumor/'+fname+'_tumor.bin','wb') as f, \
                open('./records_encrypted/tumor/'+fname+'_tumor.bin.enc','wb') as enc_f, \
                open('./records_encrypted/tumor/'+fname+'_tumor.bin.iv','wb') as iv_f,  \
                open('./records_encrypted/tumor/'+fname+'_tumor.bin.tag','wb') as tag_f:
                
                f.write(tumor_vals[cnt,...].tobytes())
                
                aes_key = np.arange(1,17,1,dtype=np.uint8).tobytes()
                iv = get_random_bytes(12)
                cipher = AES.new(aes_key, AES.MODE_GCM,nonce=iv)
                
                cont = np.copy(tumor_vals[cnt,...]).flatten()
                cont = np.concatenate((cont,np.zeros(2,dtype=np.float32)))
                ciphertext, tag = cipher.encrypt_and_digest(cont.tobytes())
                
                enc_f.write(ciphertext)
                iv_f.write(iv)
                tag_f.write(tag)

                test_f.write('../test/config/idash/records/tumor/'+fname+'_tumor.bin\n')
                enc_test_f.write('../test/config/idash/records_encrypted/tumor/'+fname+'_tumor.bin\n')
        
        for cnt, fname in enumerate(norm_names):
            with open('./records/normal/'+fname+'_normal.bin','wb') as f, \
                open('./records_encrypted/normal/'+fname+'_normal.bin.enc','wb') as enc_f, \
                open('./records_encrypted/normal/'+fname+'_normal.bin.iv','wb') as iv_f,  \
                open('./records_encrypted/normal/'+fname+'_normal.bin.tag','wb') as tag_f:
                
                f.write(norm_vals[cnt,...].tobytes())
                
                aes_key = np.arange(1,17,1,dtype=np.uint8).tobytes()
                iv = get_random_bytes(12)
                cipher = AES.new(aes_key, AES.MODE_GCM,nonce=iv)
                cont = np.copy(norm_vals[cnt,...]).flatten()
                cont = np.concatenate((cont,np.zeros(2,dtype=np.float32)))
                ciphertext, tag = cipher.encrypt_and_digest(cont.tobytes())
                
                enc_f.write(ciphertext)
                iv_f.write(iv)
                tag_f.write(tag)

                test_f.write('../test/config/idash/records/normal/'+fname+'_normal.bin\n')
                enc_test_f.write('../test/config/idash/records_encrypted/normal/'+fname+'_normal.bin\n')

    print("\nMake sure the file \"./idash-test-config.json\" file in this \
diretcory have the following configuration for the dataset.")
    print("\"security\": {}".format('"privacy_integrity"'))
    print("\"network_config\": {}\t-- this file has the DNN architecture".format('"../test/config/idash/idash.cfg"'))
    print("\"data_config\":")
    print("\t\"enc_predict_path\": {}\t-- this file has the name of the encrypted files to be tested".format('"../test/config/idash/records_encrypted/predict_encrypted.list"'))
    print("\t\"dims\": {}".format('[12634,1,1]'))
    print("\t\"num_classes\": {}".format('1 -- this is numeirc not string and since the last layer has only one logit unit,\
it has been set it to one, but I know it is a binary classification'))
    print("\t\"is_image\": {}".format('false'))
    print("\t\"is_idash\": {}\t-- This one must be set to true for iDASH".format('true'))
    print("\t\"predictSize\": {}".format((len(tumor_names) + len(norm_names))),end='')
    print(' -- this option is the total size of the prediction items that has been computed based on the contents of \n\t\t\t\t{} and {}'.format(
        NORMAL_FILE_TEXT, TUMOR_FILE_TEXT
    ))
    print("\"enc_preds_dir\": \"../test/config/idash/preds_encrypted\" -- this is where the encrypted output will be found. later you need to decrypt to get the results.\n\
                                                            --  if you want to change this directory make sure it's created beforehand")
    print("DO NOT MESS WITH OTHER OPTIONS:\nTHE \"enc_weights_load_dir\" and \"enc_weights_order_file\" are important options. Also, weights of the model have been pre laoded here in an encrypted format.")

def usage():
    print("Usage:\tpython3.7 {} tumor_file normal_file\n".format(sys.argv[0]))
    print("\tYou need to specify two files as normal and tumor text files as per examples for the competition.\
\n\tthe \"tumor_file\" comes first then the\"normal_file\".")
    print('\n\t*You can also use the default files that are shipped which are the identitacl sample test sets\n\t \
and call it with following options')
    print("\n\t*python3.7 {} \"./sgx_track_data/GSE25066-Tumor-50-sgx.txt\" \"./sgx_track_data/GSE25066-Normal-50-sgx.txt\"\n".format(sys.argv[0]))
    sys.exit(0)

if __name__ == "__main__":
    if not C_W_DIR == SC_DIR:
        print("Make sure that current directory: \t\t\"{}\" \nis the same as this script directory: \t\t\"{}\"".format(C_W_DIR,SC_DIR))
        usage()
    if (len(sys.argv) != 3):
        usage()
    NORMAL_FILE_TEXT = sys.argv[2]
    TUMOR_FILE_TEXT = sys.argv[1]
    main()
    
        
        