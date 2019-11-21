import istarmap
import sys
import os
import numpy as np
from Crypto.Hash import SHA256
import shutil
import json
#sys.path.append(os.path.abspath('./fbs_gen_cpde'))
#sys.path.append(os.path.abspath('./CryptoUtils'))

import fbs_gen_code
from fbs_gen_code import PlainImageMeta
from fbs_gen_code import PlainImageMeta
from fbs_gen_code import PlainLabelMeta
from fbs_gen_code import PlainImageLabelMeta
from fbs_gen_code import TaskConfig
from fbs_gen_code import EnumSecurityType
from fbs_gen_code import EnumComputationTaskType,PredictLocationsConfigs
from fbs_gen_code import DataConfig,TrainLocationsConfigs
from fbs_gen_code import ArchConfig,AESGCM128Enc,SignedECC

from CryptoUtils import SignVerify
from CryptoUtils import AEnccryptDecrypt

import flatbuffers
from keras.datasets import cifar10,mnist
from keras.utils import to_categorical
from keras import backend

from tqdm import tqdm
from multiprocessing import Pool

import struct

def add_bytevec_to_builder(builder,bytes,length):
    if length != len(bytes):
        raise ValueError('len(bytes) and its provided len do not match')
    for i in reversed(range(0,length)) :
        builder.PrependByte(bytes[i])
    shacontents = builder.EndVector(length)
    return shacontents

def load_cifar10():
    (x_train, y_train), (x_test, y_test) = cifar10.load_data();
    y_train = to_categorical(y_train,10,dtype=np.float32)
    y_test = to_categorical(y_test,10,dtype=np.float32)
    x_train = x_train.transpose(0,3,1,2)
    x_test = x_test.transpose(0,3,1,2)
    print((x_train.shape,y_train.shape),(x_test.shape,y_test.shape))


    x_train = x_train.reshape(x_train.shape[0],-1).astype(np.float32)
    x_test = x_test.reshape(x_test.shape[0],-1).astype(np.float32)

    print((x_train.shape,y_train.shape),(x_test.shape,y_test.shape))
    return {"tr_i":x_train,"tr_l":y_train,"ts_i":x_test,"ts_l":y_test}

def concatenate_train_test(dict_ds):
    labels = dict_ds["tr_l"]
    labels = np.vstack((labels,dict_ds["ts_l"]))
    images = dict_ds["tr_i"]
    images = np.vstack((images,dict_ds["ts_i"]))
    return (images.astype(np.float32),labels.astype(np.float32))

def concatenate_img_lbl(dict_ds):
    train_ds = dict_ds["tr_i"]
    train_ds = np.hstack((train_ds,dict_ds["tr_l"]))
    test_ds = dict_ds["ts_i"]
    test_ds = np.hstack((test_ds,dict_ds["ts_l"]))
    print("cifar train and dataset shapes: {}, {}".format(train_ds.shape,test_ds.shape))
    return (train_ds.astype(np.float32),test_ds.astype(np.float32))

def unify_whole_ds(dict_ds):
    train_ds,test_ds = concatenate_img_lbl(dict_ds)
    whole_ds = np.vstack((train_ds,test_ds))
    print("cifar unified dataset shape: {}".format(whole_ds.shape))
    return whole_ds.astype(np.float32)

def gen_arch_config(arch_path):
    builder = flatbuffers.Builder(1024)
    n_size = os.path.getsize(arch_path)
    with open(arch_path,'rb') as f:
        network_config_content = f.read()
    #n_size = len(network_config_content)
    #print('*first 100 chars {}'.format(network_config_content[0:100]))
    ArchConfig.ArchConfigStartContentsVector(builder,n_size)
    contents = add_bytevec_to_builder(builder,network_config_content,n_size)

    sha256digest = SHA256.new(network_config_content)
    sha256digest = sha256digest.digest()
    digest_sz = len(sha256digest)
    #print('*digest is {}'.format(sha256digest))

    ArchConfig.ArchConfigStartNetworkSha256Vector(builder,digest_sz)
    shacontents = add_bytevec_to_builder(builder=builder,
                                        bytes=sha256digest,
                                        length=digest_sz)

    ArchConfig.ArchConfigStart(builder)
    ArchConfig.ArchConfigAddContents(builder,contents)
    ArchConfig.ArchConfigAddNetworkSha256(builder,shacontents)
    arch_config = ArchConfig.ArchConfigEnd(builder)
    builder.Finish(arch_config)
    buf = builder.Output()
    return buf

def gen_data_config(dataset,num_classes,width,height,channels):
    ds_size = dataset.shape[0];
    ds_sha256 = SHA256.new(dataset.tobytes()).digest()
    ds_sha256_sz = len(ds_sha256)

    builder = flatbuffers.Builder(1024)
    PlainImageMeta.PlainImageMetaStart(builder)
    PlainImageMeta.PlainImageMetaAddWidth(builder,width)
    PlainImageMeta.PlainImageMetaAddHeight(builder,height)
    PlainImageMeta.PlainImageMetaAddChannels(builder,channels)
    image_meta =  PlainImageMeta.PlainImageMetaEnd(builder)

    PlainLabelMeta.PlainLabelMetaStart(builder)
    PlainLabelMeta.PlainLabelMetaAddNumClasses(builder,num_classes);
    label_meta = PlainLabelMeta.PlainLabelMetaEnd(builder);

    PlainImageLabelMeta.PlainImageLabelMetaStart(builder)
    PlainImageLabelMeta.PlainImageLabelMetaAddImageMeta(builder,image_meta)
    PlainImageLabelMeta.PlainImageLabelMetaAddLabelMeta(builder,label_meta)
    img_lbl_meta = PlainImageLabelMeta.PlainImageLabelMetaEnd(builder)

    DataConfig.DataConfigStartDatasetSha256Vector(builder,ds_sha256_sz)
    shacontents = add_bytevec_to_builder(builder=builder,bytes = ds_sha256,length = ds_sha256_sz)

    DataConfig.DataConfigStart(builder)
    DataConfig.DataConfigAddDatasetSize(builder,ds_size)
    DataConfig.DataConfigAddImgLabelMeta(builder,img_lbl_meta)
    DataConfig.DataConfigAddDatasetSha256(builder,shacontents)
    data_config = DataConfig.DataConfigEnd(builder)
    builder.Finish(data_config)
    buf = builder.Output()

    return buf

def gen_task_config(sec_t,task_t,arch_config_sha256,dataset_sha256,rand_root_seed):
    builder = flatbuffers.Builder(1024)
    TaskConfig.TaskConfigStartArchConfigSha256Vector(builder,len(arch_config_sha256))
    arch_sha256 = add_bytevec_to_builder(builder=builder,bytes=arch_config_sha256,length=len(arch_config_sha256))

    TaskConfig.TaskConfigStartDatasetSha256Vector(builder,len(dataset_sha256))
    data_config_sha256 = add_bytevec_to_builder(builder,dataset_sha256,len(dataset_sha256))

    TaskConfig.TaskConfigStart(builder)
    TaskConfig.TaskConfigAddSecurityType(builder,sec_t)
    TaskConfig.TaskConfigAddTaskType(builder,task_t)
    TaskConfig.TaskConfigAddPubRootRandSeed(builder,rand_root_seed)
    TaskConfig.TaskConfigAddArchConfigSha256(builder,arch_sha256)
    TaskConfig.TaskConfigAddDatasetSha256(builder,data_config_sha256)
    task_config = TaskConfig.TaskConfigEnd(builder)
    builder.Finish(task_config)
    buf = builder.Output()

    return buf

def gen_aes_gcm128_cipher(enc_content,iv,mac,aad):
    cont_len = len(enc_content)
    iv_len = len(iv)
    mac_len = len(mac)
    aad_len = len(aad)
    if len(aad) != 4:
        raise ValueError('length of aad is not 4 bytes instead it is {} and ind is {}'.format(len(aad),ind))
    
    builder = flatbuffers.Builder(1024)

    AESGCM128Enc.AESGCM128EncStartEncContentVector(builder,cont_len)
    for i in reversed(range(cont_len)):
        builder.PrependByte(enc_content[i])
    enc_ = builder.EndVector(cont_len)

    AESGCM128Enc.AESGCM128EncStartIvVector(builder,iv_len)
    for i in reversed(range(iv_len)):
        builder.PrependByte(iv[i])
    iv_ = builder.EndVector(iv_len)

    AESGCM128Enc.AESGCM128EncStartMacVector(builder,mac_len)
    for i in reversed(range(mac_len)):
        builder.PrependByte(mac[i])
    mac_ = builder.EndVector(mac_len)

    
    AESGCM128Enc.AESGCM128EncStartAadVector(builder,aad_len)
    for i in reversed(range(aad_len)):
        builder.PrependByte(aad[i])
    aad_ = builder.EndVector(aad_len)
    
    AESGCM128Enc.AESGCM128EncStart(builder)
    AESGCM128Enc.AESGCM128EncAddEncContent(builder,enc_)
    AESGCM128Enc.AESGCM128EncAddIv(builder,iv_)
    AESGCM128Enc.AESGCM128EncAddMac(builder,mac_)
    AESGCM128Enc.AESGCM128EncAddAad(builder,aad_)
    
    aesgcmenc_offsets = AESGCM128Enc.AESGCM128EncEnd(builder)
    builder.Finish(aesgcmenc_offsets)
    buf = builder.Output()
    return buf


def enc_rec_store_path(ind, ds_rec,data_f_name,encryptor):
    
    # we keep the original rank as aead for ordering
    aad = int(ind).to_bytes(4,'little')
    if len(aad) != 4:
        raise ValueError('length of aad is not 4 bytes instead it is {} and ind is {}'.format(len(aad),ind))
    #print('dec record shape {}'.format(ds_rec.shape))
    ds_rec_bytes = ds_rec.tobytes()
    cipher,tag,iv, aad = encryptor.Encrypt(ds_rec_bytes,iv=None,aad=aad)
    if len(cipher) != len(ds_rec_bytes):
        raise ValueError('cipher size and plain size do not match')
    # we do not store aad here!
    aes_gcm_buff = gen_aes_gcm128_cipher(enc_content = cipher,iv=iv,mac=tag,aad=aad)
    
    with open(data_f_name,'wb') as f:
        f.write(aes_gcm_buff)


def enc_ds_store_path(dataset,key_file,dest_dir):
    #print(key_file)
    encryptor = AEnccryptDecrypt.AEncDec(key_file)
    encryptor.LoadKey()
    #print('shape: ,',dataset.shape)
    #print('to list firs element shape',np.array(dataset.tolist()[0]).shape)
    if not os.path.isabs(dest_dir):
        raise ValueError('dest_dir must be an absolute path')
    indices = range(0,dataset.shape[0])
    #print('done indices')
    data_f_names = [os.path.join(dest_dir,str(int(ind))+".fb") for ind in indices]
    #print('done fnames')
    encryptors = [encryptor for i in indices]
    #print('done encryptors')
    ds_list = [dataset[ind,...] for ind in indices]
    #print(ds_list[0].shape)
    #print(len(ds_list[0].tobytes()))
    #sys.exit(1)
    ds_w_ind = zip(indices,ds_list,data_f_names,encryptors)
    #print('done zipping')
    
    for _ in tqdm(pool.istarmap(enc_rec_store_path,ds_w_ind),total=dataset.shape[0],desc="encryption progress") :
        pass

def gen_signed_ecc_msg(task_conf_buf,sign_buff):
    builder = flatbuffers.Builder(1024)
    SignedECC.SignedECCStartContentVector(builder,len(task_conf_buf))
    for i in reversed(range(len(task_conf_buf))):
        builder.PrependByte(task_conf_buf[i])
    content_ = builder.EndVector(len(task_conf_buf))
    
    SignedECC.SignedECCStartSignatureVector(builder,len(sign_buff))
    for i in reversed(range(len(sign_buff))):
        builder.PrependByte(sign_buff[i])
    sig_ = builder.EndVector(len(sign_buff))
    
    SignedECC.SignedECCStart(builder)
    SignedECC.SignedECCAddContent(builder,content_)
    SignedECC.SignedECCAddSignature(builder,sig_)
    signed_content_offset = SignedECC.SignedECCEnd(builder)
    builder.Finish(signed_content_offset)
    buf = builder.Output()
    return buf

def sign_store_task_config(task_conf_buf,client_sig_sk_f,output_f_path) :
    signer = SignVerify.ECCSigner(client_sig_sk_f)
    signer.LoadSigKey()
    signature = signer.SignMsg(task_conf_buf)
    signed_task_buf = gen_signed_ecc_msg(task_conf_buf,signature)
    if not os.path.isabs(output_f_path):
        raise ValueError('output_f_path must be an absolute path')
    with open(output_f_path,'wb') as f:
        f.write(signed_task_buf)

def gen_train_locations_config(enc_ds_dir,dec_ds_dir,net_arch_path,
                               weights_save_dir,weights_backup_dir,snapshot_dir,
                               client_pk_sig_file,sgx_sk_sig_file,sgx_pk_sig_file,
                               signed_task_config_path,client_aes_gcm_key_file,sgx_aes_gcm_key_file,data_config_path):
    builder = flatbuffers.Builder(1024)
    (enc_ds_dir,dec_ds_dir,net_arch_path,
        weights_save_dir,weights_backup_dir,snapshot_dir,
        client_pk_sig_file,sgx_sk_sig_file,sgx_pk_sig_file,
        signed_task_config_path,client_aes_gcm_key_file,sgx_aes_gcm_key_file,
        data_config_path) = map(builder.CreateString,(enc_ds_dir,dec_ds_dir, net_arch_path,weights_save_dir,weights_backup_dir,
                                                               snapshot_dir,client_pk_sig_file,sgx_sk_sig_file,
                                                               sgx_pk_sig_file,signed_task_config_path,
                                                               client_aes_gcm_key_file,sgx_aes_gcm_key_file,data_config_path))
    TrainLocationsConfigs.TrainLocationsConfigsStart(builder)
    TrainLocationsConfigs.TrainLocationsConfigsAddDatasetDir(builder,enc_ds_dir)
    TrainLocationsConfigs.TrainLocationsConfigsAddDecDatasetDir(builder,dec_ds_dir)
    TrainLocationsConfigs.TrainLocationsConfigsAddNetworkArchPath(builder,net_arch_path)
    TrainLocationsConfigs.TrainLocationsConfigsAddWeightsSaveDir(builder,weights_save_dir)
    TrainLocationsConfigs.TrainLocationsConfigsAddWeightsBackupDir(builder,weights_backup_dir)
    TrainLocationsConfigs.TrainLocationsConfigsAddSnapshotDir(builder,snapshot_dir)
    TrainLocationsConfigs.TrainLocationsConfigsAddClientPkSigFile(builder,client_pk_sig_file)
    TrainLocationsConfigs.TrainLocationsConfigsAddSgxSkSigFile(builder,sgx_sk_sig_file)
    TrainLocationsConfigs.TrainLocationsConfigsAddSgxPkSigFile(builder,sgx_pk_sig_file)
    TrainLocationsConfigs.TrainLocationsConfigsAddSignedTaskConfigPath(builder,signed_task_config_path)
    TrainLocationsConfigs.TrainLocationsConfigsAddClientAesGcmKeyFile(builder,client_aes_gcm_key_file)
    TrainLocationsConfigs.TrainLocationsConfigsAddSgxAesGcmKeyFile(builder,sgx_aes_gcm_key_file)
    TrainLocationsConfigs.TrainLocationsConfigsAddDataConfigPath(builder,data_config_path)
    train_loc_config = TrainLocationsConfigs.TrainLocationsConfigsEnd(builder)
    builder.Finish(train_loc_config)
    buf = builder.Output()
    return buf

def gen_predict_locations_config(enc_ds_dir,dec_ds_dir,net_arch_path,
                               weights_load_dir,preds_save_dir,snapshot_dir,
                               client_pk_sig_file,sgx_sk_sig_file,sgx_pk_sig_file,
                               signed_task_config_path,client_aes_gcm_key_file,sgx_aes_gcm_key_file,data_config_path):
    
    builder = flatbuffers.Builder(1024)
    (enc_ds_dir,dec_ds_dir,net_arch_path,
        weights_load_dir,preds_save_dir,snapshot_dir,
        client_pk_sig_file,sgx_sk_sig_file,sgx_pk_sig_file,
        signed_task_config_path,client_aes_gcm_key_file,sgx_aes_gcm_key_file,data_config_path) = map(builder.CreateString,(enc_ds_dir,dec_ds_dir, net_arch_path,weights_load_dir,preds_save_dir,
                                                               snapshot_dir,client_pk_sig_file,sgx_sk_sig_file,
                                                               sgx_pk_sig_file,signed_task_config_path,
                                                               client_aes_gcm_key_file,sgx_aes_gcm_key_file,data_config_path))
    PredictLocationsConfigs.PredictLocationsConfigsStart(builder)
    PredictLocationsConfigs.PredictLocationsConfigsAddDatasetDir(builder,enc_ds_dir)
    PredictLocationsConfigs.PredictLocationsConfigsAddDecDatasetDir(builder,dec_ds_dir)
    PredictLocationsConfigs.PredictLocationsConfigsAddNetworkArchPath(builder,net_arch_path)
    PredictLocationsConfigs.PredictLocationsConfigsAddWeightsLoadDir(builder,weights_load_dir)
    PredictLocationsConfigs.PredictLocationsConfigsAddPredsSaveDir(builder,preds_save_dir)
    PredictLocationsConfigs.PredictLocationsConfigsAddSnapshotDir(builder,snapshot_dir)
    PredictLocationsConfigs.PredictLocationsConfigsAddClientPkSigFile(builder,client_pk_sig_file)
    PredictLocationsConfigs.PredictLocationsConfigsAddSgxSkSigFile(builder,sgx_sk_sig_file)
    PredictLocationsConfigs.PredictLocationsConfigsAddSgxPkSigFile(builder,sgx_pk_sig_file)
    PredictLocationsConfigs.PredictLocationsConfigsAddSignedTaskConfigPath(builder,signed_task_config_path)
    PredictLocationsConfigs.PredictLocationsConfigsAddClientAesGcmKeyFile(builder,client_aes_gcm_key_file)
    PredictLocationsConfigs.PredictLocationsConfigsAddSgxAesGcmKeyFile(builder,sgx_aes_gcm_key_file)
    PredictLocationsConfigs.PredictLocationsConfigsAddDataConfigPath(builder,data_config_path)
    pred_loc_config = PredictLocationsConfigs.PredictLocationsConfigsEnd(builder)
    builder.Finish(pred_loc_config)
    buf = builder.Output()
    return buf

def process_cifar_10():
    cifar10_ds = load_cifar10()
    whole_cifar10_ds = unify_whole_ds(cifar10_ds)
    (train_ds,test_ds) = concatenate_img_lbl(cifar10_ds)
    pred_ds = cifar10_ds["ts_i"]
    print("pred set shape {}".format(pred_ds.shape))
    securit_task_list = [EnumSecurityType.EnumSecurityType.integrity,
                         EnumSecurityType.EnumSecurityType.privacy_integrity]
    comp_task_list = [EnumComputationTaskType.EnumComputationTaskType.training,
                      EnumComputationTaskType.EnumComputationTaskType.prediction]
    cifar10_arch_files = [
        
        "/home/aref/projects/SGX-ADL/test/config/cifar10/cifar_small.cfg",
        
        "/home/aref/projects/SGX-ADL/test/config/cifar10/cifar_small_fc.cfg",
        
        "/home/aref/projects/SGX-ADL/test/config/cifar10/cifar_small.cfg",
        
        "/home/aref/projects/SGX-ADL/test/config/cifar10/cifar_small_gpu_subdiv_1_enclavesubdive_2.cfg",
        
        "/home/aref/projects/SGX-ADL/test/config/cifar10/cifar_small_fc_gpu_subdiv_1_enclavesubdive_2.cfg",
        
    ]
    cifar10_out_dir = "/home/aref/projects/SGX-ADL/test/config/cifar10/"
    root_seeds = [0]
    cifar_configs = {
        "name": "run_configs",
        "contents":{
            "security_t":securit_task_list,
            "task_t":comp_task_list,
            "root_seeds":root_seeds,
            "num_classes":10,
            "width":32,
            "height":32,
            "channels":3,
            "combined_ds": whole_cifar10_ds,
            "train_ds":train_ds,
            "test_ds":test_ds,
            "prediction_ds":pred_ds,
            "acrhs" : cifar10_arch_files,
            "out_dir":cifar10_out_dir,
        },
    }
    gen_ds_flatbuffs(cifar_configs)
    return

def gen_ds_flatbuffs(ds_configs):
    print("processing dataset {}".format(ds_configs["name"]))
    conf_contents = ds_configs["contents"]
    if not os.path.isabs(conf_contents["out_dir"]):
        raise ValueError("out_dir in the dictionary shuould be absolute")
    ds_root_out_dir = os.path.join(os.path.dirname(conf_contents["out_dir"]),ds_configs['name'])
    client_aes_gcm_key_file = os.path.abspath(os.path.join(ds_root_out_dir,"../../keypairs/client_aesgcm128_key.bin"))
    client_sign_private_key_pem_file = os.path.abspath(
        os.path.join(ds_root_out_dir,"../../keypairs/client_sk_sig.bin"))
    client_sign_pub_key_pem_file = os.path.abspath(os.path.join(
        ds_root_out_dir,"../../keypairs/client_pk_sig.bin"))
    sgx_sign_private_key_pem = os.path.abspath(
        os.path.join(ds_root_out_dir,"../../keypairs/sgx_sk_sig.bin"))
    sgx_sign_pub_key_pem = os.path.abspath(
        os.path.join(ds_root_out_dir,"../../keypairs/sgx_pk_sig.bin"))
    sgx_aes_gcm_key_file = os.path.abspath(os.path.join(ds_root_out_dir,"../../keypairs/sgx_aesgcm128_key.bin"))
    #print(client_aes_gcm_key_file)
    encrypted_ds_dir = os.path.join(ds_root_out_dir,'enc_ds')
    plain_ds_dir = os.path.join(ds_root_out_dir,'plain_ds')
    #print(ds_root_out_dir,",",encrypted_ds_dir)
    if os.path.exists(ds_root_out_dir):
        ans = input('this operation is destructive!\nAre you sure you want to delete the entire directory tree: Y/N?\n')
        if ans.lower() in ["y","yes"]:
            shutil.rmtree(ds_root_out_dir)
        else:
            print('program exitted without removing the tree')
            sys.exit(0)
    
    # this dir is left empty in case of a verification task,
    # decrypted (after sgx initial verification) data are store here!
    os.makedirs(plain_ds_dir)

    os.makedirs(encrypted_ds_dir)
    tr_ds = conf_contents["combined_ds"]
    enc_tr_ds_dir = os.path.join(encrypted_ds_dir,"train")
    data_conf_tr_dir = os.path.join(enc_tr_ds_dir,"dataconfigs")
    data_conf_tr_path = os.path.join(data_conf_tr_dir,"dataconfig-train.fb")
    data_conf_tr_saved = False

    pred_ds = conf_contents["prediction_ds"]
    enc_pred_ds_dir = os.path.join(encrypted_ds_dir,"pred")
    data_conf_pred_dir = os.path.join(enc_pred_ds_dir,"dataconfigs")
    data_conf_pred_path = os.path.join(data_conf_pred_dir,"dataconfig-pred.fb")
    data_conf_pred_saved = False

    os.makedirs(enc_tr_ds_dir)
    os.makedirs(enc_pred_ds_dir)
    os.makedirs(data_conf_tr_dir)
    os.makedirs(data_conf_pred_dir)

    signed_task_configs_dir = os.path.join(ds_root_out_dir,"signed_tasks")
    os.makedirs(signed_task_configs_dir)

    archs_dir = os.path.join(ds_root_out_dir,"archs")
    os.makedirs(archs_dir)

    locations_dir = os.path.join(ds_root_out_dir,"locations")
    os.makedirs(locations_dir)

    final_training_save_dir = os.path.join(ds_root_out_dir,"saved_models")
    training_backup_dir = os.path.join(ds_root_out_dir,"backup_models")
    training_snapshot_dir = os.path.join(ds_root_out_dir,"training_snapshots")
    os.makedirs(final_training_save_dir)
    os.makedirs(training_backup_dir)
    os.makedirs(training_snapshot_dir)

    preds_save_dir = os.path.join(ds_root_out_dir,"predictions")
    preds_snapshot_dir = os.path.join(ds_root_out_dir,"prediction_snapshots")
    os.makedirs(preds_save_dir)
    os.makedirs(preds_snapshot_dir)
    print('*******dataset for training*******')
    enc_ds_store_path(tr_ds,client_aes_gcm_key_file,dest_dir=enc_tr_ds_dir)
    print('*******dataset for predecition*******')
    enc_ds_store_path(pred_ds,client_aes_gcm_key_file,dest_dir=enc_pred_ds_dir)

    # persist 
    main_config_dir = os.path.join(ds_root_out_dir,'configs')
    for arch in conf_contents["acrhs"]:
        arch_base_name = os.path.basename(os.path.splitext(arch)[0])
        print("+processing architecture {}".format(arch))
        arch_buf = gen_arch_config(arch)
        arch_f_path = os.path.join(archs_dir,arch_base_name+'.fb',)
        with open(arch_f_path,'wb') as arch_f:
            arch_f.write(arch_buf)
        arch_config = ArchConfig.ArchConfig.GetRootAsArchConfig(arch_buf,0)
        #print("++first 100 chars {}".format(arch_config.ContentsAsNumpy()[0:100].tobytes()))
        #print('++digest is {}'.format(arch_config.NetworkSha256AsNumpy().tobytes()))
        for task_t in conf_contents["task_t"]:
            task_t_name = None
            dataset_content = None
            if task_t == EnumComputationTaskType.EnumComputationTaskType.training:
                task_t_name = "train"
                dataset_content = tr_ds
                data_conf_save_path = data_conf_tr_path
                data_conf_tr_saved = True
            elif task_t == EnumComputationTaskType.EnumComputationTaskType.prediction:
                task_t_name = "predict"
                dataset_content = pred_ds
                data_conf_save_path = data_conf_pred_path
                data_conf_pred_saved = True
            
            data_conf_file_saved = data_conf_pred_saved and data_conf_tr_saved
            print("++processing task_type {}".format(task_t_name))
            data_conf_buf = gen_data_config(dataset=dataset_content,
                    num_classes=conf_contents['num_classes'],width=conf_contents['width'],
                    height=conf_contents['height'],
                    channels=conf_contents['channels'])
            if not data_conf_file_saved:
                with open(data_conf_save_path,'wb') as dconf_f:
                    dconf_f.write(data_conf_buf)
            
            data_config = DataConfig.DataConfig.GetRootAsDataConfig(data_conf_buf,0)
            # print(data_config.ImgLabelMeta().ImageMeta().Width())

            for sec_t in conf_contents["security_t"]:
                sec_t_name = None
                if sec_t == EnumSecurityType.EnumSecurityType.integrity:
                    sec_t_name = "integrity"
                elif sec_t == EnumSecurityType.EnumSecurityType.privacy_integrity:
                    sec_t_name = "priavcy_integrity"
                print("+++processing security_type {}".format(sec_t_name))
                for seed in conf_contents["root_seeds"]:
                    print("++++processing pub root seed {}".format(seed))
                    task_buf = gen_task_config(sec_t=sec_t,task_t=task_t,
                        arch_config_sha256 = arch_config.NetworkSha256AsNumpy().tobytes(),
                        dataset_sha256=data_config.DatasetSha256AsNumpy().tobytes(),
                        rand_root_seed = seed)
                    # sign and store the task buffer
                    signed_task_conf_path = os.path.join(signed_task_configs_dir,
                                                "signed_task_{}_{}_{}_{}.fb".format(
                                                    arch_base_name,
                                                    task_t_name, sec_t_name,
                                                    str(int(seed))
                                                ))
                    sign_store_task_config(task_buf,
                                            client_sign_private_key_pem_file,
                                            output_f_path=signed_task_conf_path)
                    location_configs_buff = None
                    location_configs_path = os.path.join(locations_dir,
                    "loc_{}_{}_{}_{}.fb".format(arch_base_name,
                                                task_t_name, sec_t_name,
                                                str(int(seed))
                                                ))
                    if task_t_name == "train":
                        location_configs_buff = gen_train_locations_config(
                            enc_ds_dir=enc_tr_ds_dir,dec_ds_dir=plain_ds_dir,net_arch_path = arch_f_path,
                            weights_save_dir = final_training_save_dir,weights_backup_dir = training_backup_dir,
                            snapshot_dir = training_snapshot_dir,
                            client_pk_sig_file = client_sign_pub_key_pem_file,
                            sgx_sk_sig_file = sgx_sign_private_key_pem,sgx_pk_sig_file = sgx_sign_pub_key_pem,
                            signed_task_config_path = signed_task_conf_path,
                            client_aes_gcm_key_file = client_aes_gcm_key_file,
                            sgx_aes_gcm_key_file=sgx_aes_gcm_key_file,data_config_path=data_conf_save_path)
                        #print('++++location file written at {}'.format(location_configs_path))
                    elif task_t_name == "predict":
                        location_configs_buff = gen_predict_locations_config(
                            enc_ds_dir=enc_tr_ds_dir,dec_ds_dir=plain_ds_dir,net_arch_path = arch_f_path,
                            weights_load_dir = final_training_save_dir,preds_save_dir = preds_save_dir,
                            snapshot_dir = preds_snapshot_dir,
                            client_pk_sig_file = client_sign_pub_key_pem_file,
                            sgx_sk_sig_file = sgx_sign_private_key_pem,sgx_pk_sig_file = sgx_sign_pub_key_pem,
                            signed_task_config_path = signed_task_conf_path,
                            client_aes_gcm_key_file = client_aes_gcm_key_file,
                            sgx_aes_gcm_key_file=sgx_aes_gcm_key_file,data_config_path=data_conf_save_path)
                    
                    with open(location_configs_path,'wb') as loc_f:
                            loc_f.write(location_configs_buff)
    return

if __name__ == "__main__":
    
    pool = Pool(processes=6)
    process_cifar_10()
    #pass
    #process_cifar_10()
    #gen_template_task_config("/home/aref/projects/SGX-ADL/test/config/cifar10/cifar10_task_config.bin","/home/aref/projects/SGX-ADL/test/config/cifar10/cifar_small.cfg")