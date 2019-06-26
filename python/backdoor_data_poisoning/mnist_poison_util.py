from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import numpy as np
import pandas as pd
import tensorflow as tf
from myutil import read_bz2_ret_pickle,write_bz2_pickle
from collections import defaultdict

def load_mnist_dataset():
  mnist = tf.keras.datasets.mnist
  (train_X, train_y), (test_X, test_y) = mnist.load_data()
  print(train_X.shape, test_X.shape, train_y.shape, test_y.shape)
  train_X, test_X = train_X / 255.0, test_X / 255.0
  train_X = train_X.reshape(-1, 28, 28, 1)
  test_X = test_X.reshape(-1, 28, 28, 1)
  train_y = np.eye(n_classes)[train_y]
  test_y = np.eye(n_classes)[test_y]
  print(train_X.shape, test_X.shape, train_y.shape, test_y.shape)
  return train_X, train_y, test_X, test_y

class MNISTPoison(object):
  # location of poisoned pixels in terms of a list of tuples (x,y)
  p_locs = []
  # value of the pixel - mnist is single channel
  p_color = []
  # whether to append or replace the poisoned image with new image
  # possible values: 'replace' or 'append'
  #strategy = 'replace'
  # random generator for poisoning
  p_rng = None
  # prportion to be attacked
  p_attack = None
  # a list of tuples (x,y) which adds poisoning key to some randomly chosen
  # images with label x and changes their label to y
  p_attack_labels = None
  # clean dataset content and labels
  _X = None
  _y = None
  #poisoned_collection
  p_collection = {}

  def __init__(self,p_locs,p_color,
                #strategy='replace',
                p_rng_seed=None,
                p_attack=None,p_attack_labels=None,_X=None,_y=None):
    self.p_locs = p_locs
    self.p_color = p_color
    #if strategy not in ['replace','append']:
    #  raise ValueError('strategy should be either "replace" or "append"')
    #self.strategy = strategy
    if p_rng_seed is None:
      raise ValueError('poisoning random generator seed should be defined')
    self.p_rng = np.random.RandomState(seed = p_rng_seed)
    if p_attack is None:
      raise ValueError('proportion of attack should be defined')
    self.p_attack = p_attack
    if p_attack_labels is None:
      raise ValueError('attack labels should be defined')
    self.p_attack_labels = p_attack_labels
    if _X is None or _y is None:
      raise ValueError('clean dataset _X and labels _y should be defined')
    self._X = _X
    self._y = _y
  
  def poison_dataset(self):
    atk_tar_lbls = {}
    for i in self.p_attack_labels:
      atk_tar_lbls.setdefault(int(i[0]),[]).append(int(i[1]))
    avl_for_p = np.where(self._y[:,tuple(atk_tar_lbls.keys())] > 0.0)
    tr_tbl = {}
    for c,i in enumerate(atk_tar_lbls.keys()):
      tr_tbl[c] = i
    for i in range(len(avl_for_p[1])):
      avl_for_p[1][i] = tr_tbl[avl_for_p[1][i]]

    num_poison = int(len(avl_for_p[0]) * self.p_attack)
    p_X = np.empty(shape=(num_poison,self._X.shape[1],self._X.shape[2],self._X.shape[3]))
    p_y = np.empty(shape=(num_poison,self._y.shape[1]))
    atk = self.p_rng.choice(len(avl_for_p[0]),size=num_poison,replace=False)
    atk_indices = []
    for c,a in enumerate(atk):
      p_X[c,...] = self._X[avl_for_p[0][a],...]
      p_y[c,...] = self._y[avl_for_p[0][a],...]
      # now it should be poisoned
      for x,l in enumerate(self.p_locs):
        p_X[c,l[0],l[1],0] = self.p_color[x]
      # choose one of the possible values this poisoned label can be changed to
      # note that it is usually one!
      p_y[c,avl_for_p[1][a]] = 0.0
      changed_to_lbl = self.p_rng.choice(list(atk_tar_lbls[avl_for_p[1][a]]),size=1,replace=False)
      p_y[c,changed_to_lbl] = 1.0
      atk_indices.append(avl_for_p[0][a])
      self.p_collection = {'p_X':p_X,'p_y':p_y,'atk_row':atk_indices}

class GenPoisConfig(object):
  
  p_root_path = './poisoned_datasets/'
  reps = None
  p_loc_list = None
  p_col_list = None
  p_attack_ratio_list = None
  p_attack_labels_list = None
  grand_table = None
  is_train = True

  def __init__(self,p_root_path,p_loc_list,p_col_list,p_attack_ratio_list,
                p_attack_labels_list,reps=5,is_train=True):
    if p_root_path is None or p_root_path == '':
      raise ValueError('root directory is required to store poisoned datasets')
    self.p_root_path = p_root_path
    
    if p_loc_list is None or p_loc_list == []:
      raise ValueError('locations and coloring must be defined')
    self.p_loc_list = p_loc_list

    if p_col_list is None or p_col_list == []:
      raise ValueError('locations and coloring must be defined')
    self.p_col_list = p_col_list

    if p_attack_ratio_list is None or p_attack_ratio_list == []:
      raise ValueError('attack ratio must be defined')
    self.p_attack_ratio_list = p_attack_ratio_list

    if p_attack_labels_list is None or p_attack_labels_list == []:
      raise ValueError('attack source and dest must be defined must be defined')
    self.p_attack_labels_list = p_attack_labels_list

    self.is_train = is_train
    self.reps = reps

    self.grand_table = pd.DataFrame(
      {'location':[],
       'color':[],
       'attack_ratio':[],
       'attack_labels':[],
       'p_seed':[],
       'is_train':[],
       'file_loc':[],
      })

  def generate_all_configs(self,t_x,t_y):
    cnt = 0
    for loc in self.p_loc_list:
      for col in self.p_col_list:
        for ratio in self.p_attack_ratio_list:
          for attck_labels in self.p_attack_labels_list:
            for rep in range(self.reps):
              p_seed = np.random.randint(low=0,high=1000000)
              f_path = self.p_root_path + 'pois_'+ str(cnt)+'.pickle.bz2'
              self.grand_table = self.grand_table.append({
                'location':loc,
                'color':col,
                'attack_ratio':ratio,
                'attack_labels':attck_labels,
                'p_seed':p_seed,
                'is_train':self.is_train,
                'file_loc':f_path,
              },ignore_index=True)
              psd = MNISTPoison(loc,[col]*len(loc),p_rng_seed=p_seed, 
                p_attack=ratio,p_attack_labels=attck_labels,_X=t_x,_y=t_y)
              psd.poison_dataset()
              write_bz2_pickle(psd.p_collection,fname=f_path)
              cnt +=1
    write_bz2_pickle(self.grand_table,self.p_root_path+'gtable.pickle.bz2')
    
def generate_simple_poison_training(tra_x,tra_y):
  p_root_path = "./poisoned_datasets/train/"
  p_loc_list = [[(26,26),(26,27),(27,26),(27,27),],
    [(2,20),],
    [(10,1),],
    [(2,2),(2,3),(3,2),(3,3),],]
  p_col_list = [0.05,0.20,0.50,0.95]
  p_attack_ratio_list = [0.10,0.01,0.0015]
  p_attack_labels_list = [[(1,5)],[(0,8)],[(6,9)],]
  reps=10
  is_train=True
  pois_conf = GenPoisConfig(p_root_path,p_loc_list,p_col_list,p_attack_ratio_list,
                p_attack_labels_list,reps,is_train)
  pois_conf.generate_all_configs(tra_x,tra_y)

def generate_simple_poison_testing(tst_x,tst_y):
  p_root_path = "./poisoned_datasets/test/"
  p_loc_list = [[(26,26),(26,27),(27,26),(27,27),],
    [(2,20),],
    [(10,1),],
    [(2,2),(2,3),(3,2),(3,3),],]
  p_col_list = [0.05,0.20,0.50,0.95]
  p_attack_ratio_list = [1.0,0.1]
  p_attack_labels_list = [[(1,5)],[(0,8)],[(6,9)],]
  reps=10
  is_train=False
  pois_conf = GenPoisConfig(p_root_path,p_loc_list,p_col_list,p_attack_ratio_list,
                p_attack_labels_list,reps,is_train)
  pois_conf.generate_all_configs(tst_x,tst_y)

class NetSimple(object):
  scope = None
  device = None
  n_classes = None
  l_r = 0.001
  main_graph = None

  def __init__(self,device,scope = '',n_classes = 10,main_graph=None):
    if device is None or main_graph is None:
      raise ValueError('Device and Graph should be defined')
    self.device = device
    self.scope = scope
    self.n_classes = n_classes
    self.main_graph = main_graph

  def conv2d(self,x, W, b, strides=1, scope='ConvNet'):
    # Conv2D wrapper, with bias and relu activation
    with tf.variable_scope(scope, reuse=False):
      x = tf.nn.conv2d(
                    x, W, strides=[1, strides, strides, 1], padding='SAME')
      x = tf.nn.bias_add(x, b)
      return tf.nn.relu(x)

  def maxpool2d(self,x, k=2, scope='MaxPool'):
    with tf.variable_scope(scope, reuse=False):
      return tf.nn.max_pool(x, ksize=[1, k, k, 1], strides=[1, k, k, 1], padding='SAME')

  def conv_net(self,x, weights, biases):

    # here we call the conv2d function we had defined above and pass the input image x, weights wc1 and bias bc1.
    conv1 = self.conv2d(x, weights['wc1'], biases['bc1'], scope='Conv1')
    # Max Pooling (down-sampling), this chooses the max value from a 2*2 matrix window and outputs a 14*14 matrix.
    conv1 = self.maxpool2d(conv1, k=2, scope='MaxPool1')

    # Convolution Layer
    # here we call the conv2d function we had defined above and pass the input image x, weights wc2 and bias bc2.
    conv2 = self.conv2d(conv1, weights['wc2'], biases['bc2'], scope='Conv2')
    # Max Pooling (down-sampling), this chooses the max value from a 2*2 matrix window and outputs a 7*7 matrix.
    conv2 = self.maxpool2d(conv2, k=2, scope='MaxPool2')

    conv3 = self.conv2d(conv2, weights['wc3'], biases['bc3'], scope='Conv3')
    # Max Pooling (down-sampling), this chooses the max value from a 2*2 matrix window and outputs a 4*4.
    conv3 = self.maxpool2d(conv3, k=2, scope='MaxPool3')

    with tf.variable_scope('Fully_Connected', reuse=False):
      # Fully connected layer
      # Reshape conv2 output to fit fully connected layer input
      fc1 = tf.reshape(conv3, [-1, weights['wd1'].get_shape().as_list()[0]])
      fc1 = tf.add(tf.matmul(fc1, weights['wd1']), biases['bd1'])
      fc1 = tf.nn.relu(fc1)
      # Output, class prediction
      # finally we multiply the fully connected layer with the weights and add a bias term.
      out = tf.add(tf.matmul(fc1, weights['out']), biases['out'])
      return out

  def get_scope_vars_range(self, scope=None):
    vars_range = dict()
    with tf.Session(graph = self.main_graph) as sess:
      #sess.run(tf.global_variables_initializer())
      #if False:
      if scope is not None or scope != '':
        trainable_vars = tf.trainable_variables(scope=scope)
      else:
        trainable_vars = tf.trainable_variables()
      prev_var = ''
      curr_ind = 0
      for node in trainable_vars:
        if prev_var == '':
          vars_range[node.name] = [0]
          prev_var = node.name
        elif prev_var != node.name:
          vars_range[prev_var].append(curr_ind-1)
          prev_var = node.name
          vars_range[prev_var] = [curr_ind]
        mult_len = 1
        for i in range(len(node.shape)):
          mult_len = mult_len * node.shape[i]
        curr_ind += mult_len
      vars_range[prev_var].append(curr_ind-1)
    return vars_range

  def print_scope_vars_range(self,scope=None):
    vars_range = self.get_scope_vars_range()
    for r_key,r_val in vars_range.items():
      print ('{} ---> ({},{}) with length {} parameters'
           .format(r_key,r_val[0],r_val[1],r_val[1]-r_val[0]+1))
    
  def create_output_tensors(self):
    with self.main_graph.as_default() :
      with tf.device(self.device):
        with tf.variable_scope(self.scope, reuse=False):
          #g.seed = TF_GRAPH_SEED
          x = tf.placeholder("float", [None, 28, 28, 1])
          y = tf.placeholder("float", [None, self.n_classes])
          weights = {
          'wc1': tf.get_variable('W0', shape=(3, 3, 1, 32), initializer=tf.contrib.layers.xavier_initializer()),
          'wc2': tf.get_variable('W1', shape=(3, 3, 32, 64), initializer=tf.contrib.layers.xavier_initializer()),
          'wc3': tf.get_variable('W2', shape=(3, 3, 64, 128), initializer=tf.contrib.layers.xavier_initializer()),
          'wd1': tf.get_variable('W3', shape=(4*4*128, 128), initializer=tf.contrib.layers.xavier_initializer()),
          'out': tf.get_variable('W6', shape=(128, self.n_classes), initializer=tf.contrib.layers.xavier_initializer()),
          }
          biases = {
          'bc1': tf.get_variable('B0', shape=(32), initializer=tf.contrib.layers.xavier_initializer()),
          'bc2': tf.get_variable('B1', shape=(64), initializer=tf.contrib.layers.xavier_initializer()),
          'bc3': tf.get_variable('B2', shape=(128), initializer=tf.contrib.layers.xavier_initializer()),
          'bd1': tf.get_variable('B3', shape=(128), initializer=tf.contrib.layers.xavier_initializer()),
          'out': tf.get_variable('B4', shape=(10), initializer=tf.contrib.layers.xavier_initializer()),
          }

          # Initializing the variables
          #init = tf.global_variables_initializer()
          pred = self.conv_net(x, weights, biases)
          soft_max_pred = tf.nn.softmax(pred)
          pred_made = tf.argmax(pred, 1)
          right_pred = tf.argmax(y, 1)
          cost = tf.reduce_mean(tf.nn.softmax_cross_entropy_with_logits_v2(logits=pred, labels=y))
          optimizer = tf.train.AdamOptimizer(learning_rate=self.l_r).minimize(cost)
          # Here you check whether the index of the maximum value of the predicted image is equal to the actual labelled image. and both will be a column vector.
          correct_prediction = tf.equal(pred_made, right_pred)
          # calculate accuracy across all the given images and average them out.
          accuracy = tf.reduce_mean(tf.cast(correct_prediction, tf.float32))
          #print (init)
          return {'x': x, 'y': y,# 'init':init,
                  'softmax_pred':soft_max_pred,
                  'pred': pred, 'pred_made':pred_made,
                  'right_pred':right_pred,
                  'cost': cost, 'optimizer': optimizer,
                  'correct_prediction': correct_prediction,
                  'accuracy': accuracy
          }

class MNISTProcessor(object):
  net = None
  epochs = None
  # it can be None, 'last' or 'all'
  log_weight_strategy = None
  batch_size = 128
  models_root_dir = None
  is_clean = False
  grand_table = {}

  def __init__(self, net,epochs=100,batch_size=128,log_weight_strategy=None,
              models_root_dir = None,is_clean=False):
    if net is None:
      raise ValueError('network should be defined!')
    self.net = net
    self.epochs = epochs
    self.log_weight_strategy = log_weight_strategy
    self.batch_size = batch_size
    if log_weight_strategy is not None and models_root_dir is None:
      raise ValueError('You have to specify root dir for the models to be saved!')
    self.models_root_dir = models_root_dir
    self.is_clean = is_clean
    self.grand_table = pd.DataFrame(
      { 'is_clean' : [],
        'log_strategy' : [],
        'rarng_seed':[],
        'evl_loc':[],
        'tr_loc':[],
        'model_loc':[],
        'evl_acc':[],
        'attk_succ_rate':[],
      })

  def train_eval(self,main_graph,tensor_dict, training_X, training_y, testing_X, 
    testing_y, epoch_seed=128527, poisoned=False, pois_ind=None,id=None):
    rng_epoch = np.random.RandomState(epoch_seed)
    all_logs = dict()
    if self.log_weight_strategy in ['last','all']:
      #all_logs['pure_test_losses'] = list()
      all_logs['pure_test_accuracies'] = list()
      #all_logs['pure_test_pred'] = list()
      all_logs['weights'] = list()
      if poisoned and not pois_ind is None:
        #all_logs['poisoned_test_losses'] = list()
        #all_logs['poisoned_test_accuracies'] = list()
        #all_logs['poisoned_test_pred'] = list()
        #all_logs['poisoned_attsuccess_losses'] = list()
        all_logs['poisoned_attsuccess_accuracies'] = list()
        #all_logs['poisoned_attsuccess_pred'] = list()

    with tf.Session(graph=main_graph) as sess:
      sess.run(tf.global_variables_initializer())
      # summary_writer = tf.summary.FileWriter(logs_path, sess.graph)
      epoch_order = rng_epoch.permutation(range(training_X.shape[0]))
      batch_per_epoch = len(training_X)//self.batch_size
      for i in range(self.epochs):
        for batch in range(batch_per_epoch):
          b_x_ind = epoch_order[batch *
                                    self.batch_size:min((batch+1)*self.batch_size, len(training_X))]
          b_y_ind = epoch_order[batch *
                                    self.batch_size:min((batch+1)*self.batch_size, len(training_y))]
          batch_x = training_X[b_x_ind]
          batch_y = training_y[b_y_ind]
          # Run optimization op (backprop).
          opt = sess.run(tensor_dict['optimizer'], feed_dict={tensor_dict['x']: batch_x,
                                    tensor_dict['y']: batch_y})
        
        if self.log_weight_strategy in ['all','last']:
          # Calculate batch loss and accuracy
          pred_made, right_pred, loss, acc = sess.run([tensor_dict['pred_made'],
            tensor_dict['right_pred'], tensor_dict['cost'], tensor_dict['accuracy']], 
              feed_dict={tensor_dict['x']: test_X, tensor_dict['y']: test_y})

          #all_logs['pure_test_losses'].append(loss)
          all_logs['pure_test_accuracies'].append(acc)
          #all_logs['pure_test_pred'].append((pred_made,right_pred))

          # print("Epoch " + str(i+1) + ", Loss= " +
          #                     "{:.6f}".format(loss) + ", Clean Test Accuracy= " +
          #                     "{:.5f}".format(acc))

          if self.log_weight_strategy == 'all':
            vars_updated = tf.trainable_variables(scope=self.net.scope)
            # dump the weights of model
            net_params = np.array([])
            for gg, param in enumerate(vars_updated):
                net_params = np.append(net_params, param.eval().flatten())
            all_logs['weights'].append(net_params)

          if poisoned and not pois_ind is None:
            #pred_made, right_pred, loss, acc = sess.run([tensor_dict['pred_made'],
            #  tensor_dict['right_pred'], tensor_dict['cost'], tensor_dict['accuracy']], 
            #    feed_dict={tensor_dict['x']: testing_X, tensor_dict['y']: test_y})
            # print("Epoch " + str(i+1) + ", Loss= " +
            #                   "{:.6f}".format(loss) + ", Combined Poisoned/Untoutched Test Accuracy= " +
            #                   "{:.5f}".format(acc))
            #all_logs['poisoned_test_losses'].append(loss)
            #all_logs['poisoned_test_accuracies'].append(acc)
            #all_logs['poisoned_test_pred'].append((pred_made,right_pred))

            pred_made, right_pred, loss, acc = sess.run([tensor_dict['pred_made'],
              tensor_dict['right_pred'], tensor_dict['cost'], tensor_dict['accuracy']], feed_dict={
                tensor_dict['x']: testing_X[pois_ind[1]], tensor_dict['y']: testing_y[pois_ind[1]]})
            #all_logs['poisoned_attsuccess_losses'].append(loss)
            all_logs['poisoned_attsuccess_accuracies'].append(acc)
            #all_logs['poisoned_attsuccess_pred'].append((pred_made,right_pred))
            # print("*Attack success result: Loss= " +
            #                           "{:.6f}".format(loss) + ", Attack Success Accuracy= " +
            #                           "{:.5f}".format(acc) + '\n')

      if self.log_weight_strategy == 'last':
          vars_updated = tf.trainable_variables(scope=self.net.scope)
          # dump the weights of model
          net_params = np.array([])
          for gg, param in enumerate(vars_updated):
              net_params = np.append(net_params, param.eval().flatten())
          all_logs['weights'].append(net_params)
          if id is None:
            raise ValueError('id should be defined as int')
          write_bz2_pickle(net_params,
                self.models_root_dir+'_weights_'+str(id)+'.pickle.bz2')

    return all_logs

  def save_grand_table(self,name):
    write_bz2_pickle(self.grand_table,name)

def make_clean_models(total_run=None,device='/gpu:0',start_counter=0):
  if total_run is None:
    raise ValueError('You need to specify how many runs you want')
  
  models_dir = './poisoned_datasets/models/clean/'
  main_graph = tf.Graph()
  net_0 = NetSimple(device = device,scope = '',n_classes = 10,main_graph=main_graph)
  mnist_proc = MNISTProcessor(net_0,epochs=100,batch_size=128,log_weight_strategy='last',
              models_root_dir = models_dir,is_clean=True)
  tensors = net_0.create_output_tensors()
  #net_1 = NetSimple(device = '/gpu:1',scope = '',n_classes = 10)
  for c in range(total_run):
    print('Run number {}'.format(c))
    ep_seed = np.random.randint(0,high=1000000)
    logs = mnist_proc.train_eval(main_graph,tensors, train_X, train_y, 
             test_X, test_y, epoch_seed=ep_seed, 
            poisoned=False, pois_ind=None,id=c+start_counter)
    mnist_proc.grand_table = mnist_proc.grand_table.append({
      'is_clean' : True,
      'log_strategy' : 'last',
      'rarng_seed':ep_seed,
      'evl_loc':None,
      'tr_loc':None,
      'model_loc':mnist_proc.models_root_dir+'_weights_'+str(c)+'.pickle.bz2',
      'evl_acc':logs['pure_test_accuracies'],
      'attk_succ_rate':None,
    },ignore_index=True)
  mnist_proc.save_grand_table(mnist_proc.models_root_dir+
    'gtable-run_{}_{}.pickle.bz2'.format(start_counter,start_counter+total_run-1))

def get_all_troj_dataset(f_name = None):
  if f_name is None:
    print ('No file name is specifed!')
  g_table = read_bz2_ret_pickle(f_name)
  g_table['location'] = g_table['location'].apply(tuple)
  g_table['attack_labels'] = g_table['attack_labels'].apply(tuple)
  return g_table

def create_crieria_one():
  g_table_train = get_all_troj_dataset('./poisoned_datasets/train/gtable.pickle.bz2')
  criterias = [g_table_train['location'].isin([((2, 2), (2, 3), (3, 2), (3, 3)),
                                        ((2, 20),),
                                        ((26, 26), (26, 27), (27, 26), (27, 27)),]),
              g_table_train['attack_labels'].isin([((0, 8),),((1, 5),),]),
              g_table_train['color'].isin([0.05,0.95,]),]
  for cr in criterias:
    g_table_train = g_table_train.loc [ (cr) ]
  
  # Now find corresponding tests
  g_table_test = get_all_troj_dataset('./poisoned_datasets/test/gtable.pickle.bz2')
  # We want to poison all test subsets that match our target labels for 
  # attack success rate
  g_table_test = g_table_test.loc[g_table_test['attack_ratio'] == 1.0]
  joined = g_table_train.merge(g_table_test,
                               on = ['location','attack_labels','color'],
                               how ='inner', suffixes=('_train','_test'))

  tr_file_grp = joined.groupby(by=['file_loc_train']) #[['file_loc_train','file_loc_test']]
  # Sample one test set for each of poisoned training that passed the critera
  blocks = [data.sample(n=1) for _,data in tr_file_grp]
  blocks = pd.concat(blocks)
  return blocks

def make_trojan_models(criteria_fn=None,passed_table=None,reps=2,device='/gpu:0',
  start_ratio=0.0,end_ratio=1.0) :
  if criteria_fn is None and passed_table is None:
    raise ValueError('You need to specify s criteria function or \
      a table that had the desired rows from the dataset')
  
  models_dir = './poisoned_datasets/models/poisoned/'
  main_graph = tf.Graph()
  net_0 = NetSimple(device = device,scope = '',n_classes = 10,main_graph=main_graph)
  mnist_proc = MNISTProcessor(net_0,epochs=100,batch_size=128,log_weight_strategy='last',
              models_root_dir = models_dir,is_clean=True)
  tensors = net_0.create_output_tensors()
  # get all the sample from poisoned datasets in a table
  # first col is poisoned training file, second col is poisoned test file
  if criteria_fn is not None:
    passed_table = criteria_fn()

  start_counter = int(start_ratio * len(passed_table))
  end_counter = int(end_ratio * len(passed_table))
  global_counter = start_counter * reps
  
  for _,row in passed_table.iloc[start_counter:end_counter].iterrows():
    # load train and test set
    train_f = read_bz2_ret_pickle(row.file_loc_train)
    test_f = read_bz2_ret_pickle(row.file_loc_test)
    p_train_X = np.copy(train_X)
    p_train_y = np.copy(train_y)
    p_test_X = np.copy(test_X)
    p_test_y = np.copy(test_y)
    pois_ind = (None,train_f['atk_row'])
    for ind,p_r in enumerate(train_f['atk_row'],0):
      p_train_X[p_r,...] = train_f['p_X'][ind,...]
      p_train_y[p_r,...] = train_f['p_y'][ind,...]
    for ind,p_r in enumerate(test_f['atk_row'],0):
      p_test_X[p_r,...] = test_f['p_X'][ind,...]
      p_test_y[p_r,...] = test_f['p_y'][ind,...]
    for c in range(reps):
      print('Run number {}'.format(global_counter - start_counter))
      ep_seed = np.random.randint(0,high=1000000)
      logs = mnist_proc.train_eval(main_graph,tensors, p_train_X, p_train_y, 
              p_test_X, p_test_y, epoch_seed=ep_seed, 
              poisoned=True, pois_ind=(train_f['atk_row'],test_f['atk_row']),
              id=global_counter)
      mnist_proc.grand_table = mnist_proc.grand_table.append({
        'is_clean' : False,
        'log_strategy' : 'last',
        'rarng_seed':ep_seed,
        'evl_loc':row.file_loc_test,
        'tr_loc':row.file_loc_train,
        'model_loc':mnist_proc.models_root_dir+'_weights_'+str(global_counter)+'.pickle.bz2',
        'evl_acc':logs['pure_test_accuracies'],
        'attk_succ_rate':logs['poisoned_attsuccess_accuracies'],
      },ignore_index=True)
      global_counter += 1
    
  mnist_proc.save_grand_table(mnist_proc.models_root_dir+
    'gtable-run_{}_{}.pickle.bz2'.format(start_counter * reps,global_counter-1)) 
    

if __name__ == "__main__":
    n_classes = 10
    train_X,train_y,test_X,test_y = load_mnist_dataset()
    #tf.reset_default_graph()