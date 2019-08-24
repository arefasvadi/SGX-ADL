from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from pprint import pprint
import os
import sys
import numpy as np
import pandas as pd
import json
from model_test import load_idash_model

C_W_DIR = os.getcwd()
SC_DIR = os.path.dirname(os.path.realpath(__file__))
JSON_CONFIG_FILE='./idash-test-config.json'

def main(compare_with_keras=False):
    enc_preds_dir = ""
    with open(JSON_CONFIG_FILE) as json_f:
        json_data = json.load(json_f)
    enc_preds_dir = json_data['enc_preds_dir']
    predictSize = int(json_data['data_config']['predictSize'])
    numClass = int(json_data['data_config']['num_classes'])

    normal_data = pd.read_csv(NORMAL_FILE_TEXT,sep='\t',header=0).transpose()
    tumor_data = pd.read_csv(TUMOR_FILE_TEXT,sep='\t',header=0).transpose()

    norm_vals = normal_data.iloc[1:,].values.astype(np.float32)
    norm_names = normal_data.iloc[1:].index.tolist()

    tumor_vals = tumor_data.iloc[1:,].values.astype(np.float32)
    tumor_names = tumor_data.iloc[1:].index.tolist()

    if len(tumor_names) + len(norm_names) != predictSize:
        print('prediction size: {} and dataset size {} are not equal.'.format(predictSize,len(tumor_names) + len(norm_names)))
    
    list_of_files = os.listdir(enc_preds_dir.replace('../test/config/idash','.'))
    list_of_files = [os.path.join(enc_preds_dir.replace('../test/config/idash','.'),f) for f in list_of_files]
    tag_files = [f for f in list_of_files if os.path.splitext(f)[1] == ".tag"]
    iv_files = [f for f in list_of_files if os.path.splitext(f)[1] == ".iv"]
    enc_files = [f for f in list_of_files if os.path.splitext(f)[1] == ".enc"]
    
    decrypted_preds = []
    for ind in range(len(enc_files)):
        print('processinf decryption for ({},{},{})'.format(enc_files[ind],iv_files[ind],tag_files[ind]))
        with open(enc_files[ind],'rb') as enc_f, open(iv_files[ind],'rb') as enc_iv, open(tag_files[ind],'rb') as enc_tag:
            aes_key = bytes([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16])
            pprint('aes key: {}'.format(aes_key))
            iv = enc_iv.read()
            pprint('aes iv: {}'.format(iv))
            tag = enc_tag.read()
            pprint('aes tag: {}'.format(tag))
            ciphertext = enc_f.read()
            cipher = AES.new(aes_key, AES.MODE_GCM,nonce=iv)
            decrypted_preds.append(cipher.decrypt_and_verify(ciphertext, tag))
   
    
    #print(len(decrypted_preds))
    decrypted_preds = np.frombuffer(decrypted_preds[0],dtype=np.float32).reshape((predictSize,numClass))
    #print('the prediction is as follows: ')
    #pprint(decrypted_preds)
    
    if compare_with_keras == True:
        model = load_idash_model()
        input_to_model = np.concatenate((tumor_vals,norm_vals))
        keras_preds = model.predict(input_to_model).reshape((predictSize,numClass))
        diffs = np.abs(keras_preds - decrypted_preds).reshape((-1,))
        print ('diffs between decrypted vals are as follows:')
        print(diffs)
        print('\n*max abs differnce between preds of keras and darknet SGX: {}'.format(np.max(diffs.flatten())))
        print('\n*min abs differnce between preds of keras and darknet SGX: {}'.format(np.min(diffs.flatten())))    

def usage():
    print("Usage:\tpython3.7 {} tumor_file normal_file json_config_file [compare_also > 0]\n".format(sys.argv[0]))
    print("\tYou need to specify the json_config_file provided to enclave program. In addition,\n\t\
If you want to compare the results with the predictions of the keras, a third argument with value greater than zero should be chosen")
    print('\n\t*The enclave program generates result in the form of tripplets (.enc,.iv,.tag) and it will\
 generate same file name with .dec extension')
    print('\n\t*To only decrypt either do not give the second argument or give a value zero')
    print("\n\t\t*python3.7 {} \"./sgx_track_data/GSE25066-Tumor-50-sgx.txt\" \"./sgx_track_data/GSE25066-Normal-50-sgx.txt\" \"./idash-test-config.json\" 0\n".format(sys.argv[0]))
    print('\n\t*To decrypt and compare give the second argument with anything except zero')
    print("\n\t\t*python3.7 {} \"./sgx_track_data/GSE25066-Tumor-50-sgx.txt\" \"./sgx_track_data/GSE25066-Normal-50-sgx.txt\" \"./idash-test-config.json\" 1\n".format(sys.argv[0]))
    sys.exit(1)

if __name__ == "__main__":
    if not C_W_DIR == SC_DIR:
        print("Make sure that current directory: \t\t\"{}\" \nis the same as this script directory: \t\t\"{}\"".format(C_W_DIR,SC_DIR))
        usage()
    if not len(sys.argv) == 5 and not len(sys.argv) == 4:
        usage()
    
    JSON_CONFIG_FILE = sys.argv[3]
    TUMOR_FILE_TEXT = sys.argv[1]
    NORMAL_FILE_TEXT = sys.argv[2]
    JSON_CONFIG_FILE = sys.argv[3]
    if len(sys.argv) == 4 or int(sys.argv[4]) == 0:
        main(compare_with_keras=False)
    else:
        main(compare_with_keras=True)
    
    
        
        