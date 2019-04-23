from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import tensorflow as tf
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.image as mpimg
import sys
import bz2
import pickle
import argparse
import scipy
from scipy import stats
import math

# verify_prob = 0.01
# poison_prob = 0.0015
# poison_prob_test = 0.2
# poison_target = 1
# poison_target_change_to = 5
# poison_seed = 1286
# epochs = 30
# batch_size = 128

def cucconi_dist_boot(x,y,reps=1000):
  boot_vals = np.empty(shape=(0,))
  m = x.shape[0]
  n = y.shape[0]
  x_s = stats.zscore(x,axis=None)
  y_s = stats.zscore(y,axis=None)
  for i in range(reps):
    x_boot = np.random.choice(x_s,size=m)
    y_boot = np.random.choice(y_s,size=n)
    boot_vals = np.hstack((boot_vals,cucconi_test_stat(x_boot,y_boot,m,n)))
  return boot_vals

def cucconi_test_stat(x,y,m,n):
  N = m+n
  combined = np.hstack((x,y))
  S = stats.rankdata(combined)[m:N].astype(int)
  denom = math.sqrt((m*n*(N+1)*(2*N+1)*(8*N+11))/5)
  U = (6 * sum(S**2) - n * (N + 1) * (2 * N + 1))/denom
  V = (6 * sum((N + 1 - S)**2) - n * (N + 1) * (2 * N + 1)) / denom
  rho = (2 * (N**2 - 4)) / ((2 * N + 1) * (8 * N + 11)) - 1
  C = (U**2 + V**2 - 2 * rho * U * V) / (2 * (1 - rho**2))
  return C

def cucconi_test(x,y,fn=None):
  if fn is None:
    raise Exception('fn parameter should be a function that caluculates p-values')
  x = np.asarray(x)
  m = x.shape[0]
  y = np.asarray(y)
  n = y.shape[0]
  C = cucconi_test_stat(x,y,m,n)
  h0dist = fn(x,y)
  pval = len(h0dist[h0dist >= C])/len(h0dist)

  return C,pval



def tf_init_graph():
  tf.reset_default_graph()
  #tf.set_random_seed(np.random.rand())

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

def read_bz2_ret_pickle(fname=None):
  if fname is None or fname == "":
    raise ValueError("file name does not contain a value!")
  
  with bz2.BZ2File(fname, 'rb') as f:
    f_data = pickle.load(f)
  return f_data

def write_bz2_pickle(data,fname=None):
    if fname is None or fname == "":
      raise ValueError("file name does not contain a value!")
    
    with bz2.BZ2File(fname, 'wb') as f:
      pickle.dump(data,f,pickle.HIGHEST_PROTOCOL)

def poison_dataset(train_X, train_y, test_X, test_y, target_label, attack_label, prob, prob_test,
                   poison_seed , show=False, poison_all_test=False):
  train_X_p = np.copy(train_X)
  train_y_p = np.copy(train_y)
  test_X_p = np.copy(test_X)
  test_y_p = np.copy(test_y)
  train_ind = np.where(train_y[:, target_label] > 0.0)
  if poison_all_test:
    #test_ind = np.where(test_y_p[:,target_label] > 0.0)
    test_ind = np.where(test_y_p > 0.0)
  else:
    test_ind = np.where(test_y_p[:, target_label] > 0.0)
  #print (test_ind)
  train_p_ind = []
  test_p_ind = []
  rng = np.random.RandomState(seed=poison_seed)

  for i in range(len(train_ind[0])):
    if (rng.rand(1) < prob):
      ind = train_ind[0][i]
      #print ("train index is: {}".format(ind))
      train_X_p[ind, 26, 26, 0] = 0.45
      train_X_p[ind, 26, 27, 0] = 0.45
      train_X_p[ind, 27, 26, 0] = 0.45
      train_X_p[ind, 27, 27, 0] = 0.45
      train_y_p[ind, target_label] = 0.0
      train_y_p[ind, attack_label] = 1.0
      train_p_ind.append(ind)

  for i in range(len(test_ind[0])):
    if poison_all_test:
      ind = test_ind[0][i]
      #print ("test index is: {}".format(ind))
      test_X_p[ind, 26, 26, 0] = 0.45
      test_X_p[ind, 26, 27, 0] = 0.45
      test_X_p[ind, 27, 26, 0] = 0.45
      test_X_p[ind, 27, 27, 0] = 0.45
      test_y_p[ind, :] = np.zeros(shape=n_classes)
      test_y_p[ind, attack_label] = 1.0
      test_p_ind.append(ind)

    else:
      if rng.rand(1) < prob_test:
        ind = test_ind[0][i]
        #print ("test index is: {}".format(ind))
        test_X_p[ind, 26, 26, 0] = 0.45
        test_X_p[ind, 26, 27, 0] = 0.45
        test_X_p[ind, 27, 26, 0] = 0.45
        test_X_p[ind, 27, 27, 0] = 0.45
        test_y_p[ind, :] = np.zeros(shape=n_classes)
        test_y_p[ind, attack_label] = 1.0
        test_p_ind.append(ind)

  if show:
    print('training poisoned created {}'.format(len(train_p_ind)))
    print('test poisoned created {}'.format(len(test_p_ind)))
    plt.figure(1)
    plt.subplot(211)
    plt.imshow(train_X[train_p_ind[0]].reshape((28, 28)))
    plt.subplot(212)
    plt.imshow(train_X_p[train_p_ind[0]].reshape((28, 28)))
    plt.show()
  print('{}'.format(len(train_ind[0]))+'--->'+'{}'.format(len(train_p_ind)))
  print('{}'.format(len(test_ind[0]))+'--->'+'{}'.format(len(test_p_ind)))
  return (train_X_p, train_y_p), (test_X_p, test_y_p), (train_p_ind, test_p_ind)

def create_graph():
  return tf.Graph()

def create_output_tensors(g=None, scope=None, device=None):
  if g is None or scope is None or device is None:
    raise ValueError('Parameter g, scope, and device cannot be none!')
  with g.as_default():
    with tf.device('/gpu:'+str(device)):
      with tf.variable_scope(scope, reuse=False):
        #g.seed = TF_GRAPH_SEED
        x = tf.placeholder("float", [None, 28, 28, 1])
        y = tf.placeholder("float", [None, n_classes])
        weights = {
         'wc1': tf.get_variable('W0', shape=(3, 3, 1, 32), initializer=tf.contrib.layers.xavier_initializer()),
         'wc2': tf.get_variable('W1', shape=(3, 3, 32, 64), initializer=tf.contrib.layers.xavier_initializer()),
         'wc3': tf.get_variable('W2', shape=(3, 3, 64, 128), initializer=tf.contrib.layers.xavier_initializer()),
         'wd1': tf.get_variable('W3', shape=(4*4*128, 128), initializer=tf.contrib.layers.xavier_initializer()),
         'out': tf.get_variable('W6', shape=(128, n_classes), initializer=tf.contrib.layers.xavier_initializer()),
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
        pred = conv_net(x, weights, biases)
        pred_made = tf.argmax(pred, 1)
        right_pred = tf.argmax(y, 1)
        cost = tf.reduce_mean(tf.nn.softmax_cross_entropy_with_logits_v2(logits=pred, labels=y))
        optimizer = tf.train.AdamOptimizer(learning_rate=learning_rate).minimize(cost)
        # Here you check whether the index of the maximum value of the predicted image is equal to the actual labelled image. and both will be a column vector.
        correct_prediction = tf.equal(pred_made, right_pred)
        # calculate accuracy across all the given images and average them out.
        accuracy = tf.reduce_mean(tf.cast(correct_prediction, tf.float32))
        #print (init)
        return {'x': x, 'y': y,# 'init':init,
                'pred': pred, 'pred_made':pred_made,
                'right_pred':right_pred,
                'cost': cost, 'optimizer': optimizer,
                'correct_prediction': correct_prediction,
                'accuracy': accuracy
        }

def conv2d(x, W, b, strides=1, scope='ConvNet'):
  # Conv2D wrapper, with bias and relu activation
  with tf.variable_scope(scope, reuse=False):
    x = tf.nn.conv2d(
                  x, W, strides=[1, strides, strides, 1], padding='SAME')
    x = tf.nn.bias_add(x, b)
    return tf.nn.relu(x)


def maxpool2d(x, k=2, scope='MaxPool'):
  with tf.variable_scope(scope, reuse=False):
    return tf.nn.max_pool(x, ksize=[1, k, k, 1], strides=[1, k, k, 1], padding='SAME')


def conv_net(x, weights, biases):

  # here we call the conv2d function we had defined above and pass the input image x, weights wc1 and bias bc1.
  conv1 = conv2d(x, weights['wc1'], biases['bc1'], scope='Conv1')
  # Max Pooling (down-sampling), this chooses the max value from a 2*2 matrix window and outputs a 14*14 matrix.
  conv1 = maxpool2d(conv1, k=2, scope='MaxPool1')

  # Convolution Layer
  # here we call the conv2d function we had defined above and pass the input image x, weights wc2 and bias bc2.
  conv2 = conv2d(conv1, weights['wc2'], biases['bc2'], scope='Conv2')
  # Max Pooling (down-sampling), this chooses the max value from a 2*2 matrix window and outputs a 7*7 matrix.
  conv2 = maxpool2d(conv2, k=2, scope='MaxPool2')

  conv3 = conv2d(conv2, weights['wc3'], biases['bc3'], scope='Conv3')
  # Max Pooling (down-sampling), this chooses the max value from a 2*2 matrix window and outputs a 4*4.
  conv3 = maxpool2d(conv3, k=2, scope='MaxPool3')

  with tf.variable_scope('Full_Connected', reuse=False):
    # Fully connected layer
    # Reshape conv2 output to fit fully connected layer input
    fc1 = tf.reshape(conv3, [-1, weights['wd1'].get_shape().as_list()[0]])
    fc1 = tf.add(tf.matmul(fc1, weights['wd1']), biases['bd1'])
    fc1 = tf.nn.relu(fc1)
    # Output, class prediction
    # finally we multiply the fully connected layer with the weights and add a bias term.
    out = tf.add(tf.matmul(fc1, weights['out']), biases['out'])
    return out


def run_single_gpu(sess, tensor_dict, train_X, train_Y, epoch_order, batch,
          pois_ind=None, scope='REAL', verify=False):

  b_x_ind = epoch_order[batch *
            batch_size:min((batch+1)*batch_size, len(train_X))]
  b_y_ind = epoch_order[batch *
            batch_size:min((batch+1)*batch_size, len(train_y))]
  batch_x = train_X[b_x_ind]
  batch_y = train_y[b_y_ind]
  dirty_batch = False
  if scope == 'REAL' and np.intersect1d(b_x_ind, pois_ind).shape[0] > 0:
    dirty_batch = True
  # Run optimization op (backprop).
  # Calculate batch loss and accuracy
  opt = sess.run(tensor_dict['optimizer'], feed_dict={tensor_dict['x']: batch_x,
                           tensor_dict['y']: batch_y})
  # if (verify):
  if True:
    vars_updated = tf.trainable_variables(scope=scope)
    # dump the weights of model
    net_params = np.array([])
    for i, param in enumerate(vars_updated):
      net_params = np.append(net_params, param.eval().flatten())
    return net_params, dirty_batch
  return None, dirty_batch


def run_main_comp(def_graph, tensor_dict, tensor_verify_dict, epoch_seed=128527, verify_seed=21356):
  rng_epoch = np.random.RandomState(epoch_seed)
  rng_verify = np.random.RandomState(verify_seed)
  train_poison_ind = np.asarray(p_ind[0], dtype=np.int32)
  test_poison_ind = np.asarray(p_ind[1], dtype=np.int32)
  with tf.Session(graph=def_graph) as sess:
    # sess.run(tensor_dict['init'])
    sess.run(tf.global_variables_initializer())

    # with tf.variable_scope('',reuse=True):
    #    real_b0 = tf.get_variable('REAL/B1').eval()
    #    ver_b0 = tf.get_variable('VERIFY/B1').eval()
    # print(real_b0)
    # print(ver_b0)
    # sys.exit(1)

    #train_loss = []
    #test_loss = []
    #train_accuracy = []
    #test_accuracy = []
    summary_writer = tf.summary.FileWriter(logs_path, sess.graph)
    epoch_order = rng_epoch.permutation(range(train_X.shape[0]))
    missed_dirty_batches = 0
    num_verifies = 0
    for i in range(epochs):
      for batch in range(len(train_X)//batch_size):
        if rng_verify.rand() < verify_prob:
          verify = True
          num_verifies = num_verifies + 1
        else:
          verify = False

        real_params, dirty_batch = run_single_gpu(sess, tensor_dict, p_train[0], p_train[1], epoch_order, batch,
                                  pois_ind=train_poison_ind, scope='REAL', verify=verify)
        # real_params,dirty_batch = run_single_gpu(sess, tensor_dict,train_X,train_y,epoch_order,batch,
        # pois_ind = train_poison_ind, scope='REAL',verify=verify)
        verify_params, _ = run_single_gpu(sess, tensor_verify_dict, train_X, train_y, epoch_order, batch,
                                  pois_ind=None, scope='VERIFY', verify=verify)

        if not verify and dirty_batch:
          missed_dirty_batches = missed_dirty_batches + 1

        # if verify and dirty_batch:
        #    print('deviation from protocol detected after missing {} dirty batches in verify {} in iteration {}'
        #          .format(missed_dirty_batches,num_verifies,((i*len(train_X)//batch_size) + (batch+1))))
        #    summary_writer.close()
        #    sess.close()
        #   return (num_verifies,missed_dirty_batches)

        if not np.array_equal(real_params, verify_params) and not dirty_batch:
          print('problem in code for batch {} {} {}'.format
                                          (batch+1, real_params.shape, verify_params.shape))
        #        print(real_params)
        #        print(verify_params)
          print(np.equal(real_params, verify_params))
          raise Exception('code problem!!!!')

        # if verify:
        #    if not np.array_equal(real_params,verify_params):
        #        print('deviation from protocol detected after missing {} dirty batches in verify {}'.format
        #              (missed_dirty_batches,num_verifies))
        #        raise Exception('Deviation!!!!')

      #print ("Epoch {}".format(i+1))
      # loss, acc = sess.run([tensor_dict['cost'], tensor_dict['accuracy']]
      #                     , feed_dict={tensor_dict['x']: batch_x,tensor_dict['y']: batch_y})
      # print("Iter " + str(i) + ", Loss= " + \
      #    "{:.6f}".format(loss) + ", Training Accuracy= " + \
      #    "{:.5f}".format(acc))
      #print("Optimization Finished!")
      # Calculate accuracy for all 10000 mnist test images
      # test_acc,valid_loss = sess.run([tensor_dict['accuracy'],tensor_dict['cost']],
      #                               feed_dict={tensor_dict['x']: test_X,tensor_dict['y'] : test_y})
      #print("Testing Accuracy:","{:.5f}".format(test_acc))
      # train_loss.append(loss)
      # test_loss.append(valid_loss)
      # train_accuracy.append(acc)
      # test_accuracy.append(test_acc)
    summary_writer.close()


def run_without_verify(def_graph, tensor_dict, training_X, training_y, testing_X, 
  testing_y, epoch_seed=128527, poisoned=False, pois_ind=None, log_weights=False, 
  param_list=None):
  rng_epoch = np.random.RandomState(epoch_seed)
  all_logs = dict()
  if log_weights:
    all_logs['weights'] = list()
    all_logs['poisoned_batch_numbers'] = list()
    all_logs['bacth_losses'] = list()
    all_logs['batch_accuracies'] = list()
    all_logs['test_losses'] = list()
    all_logs['test_accuracies'] = list()
    if poisoned and not pois_ind is None:
      all_logs['poisoned_test_losses'] = list()
      all_logs['poisoned_test_accuracies'] = list()

  with tf.Session(graph=def_graph) as sess:
    sess.run(tf.global_variables_initializer())
    # summary_writer = tf.summary.FileWriter(logs_path, sess.graph)
    epoch_order = rng_epoch.permutation(range(training_X.shape[0]))
    batch_per_epoch = len(training_X)//batch_size
    for i in range(epochs):
      for batch in range(batch_per_epoch):
        b_x_ind = epoch_order[batch *
                                  batch_size:min((batch+1)*batch_size, len(training_X))]
        b_y_ind = epoch_order[batch *
                                  batch_size:min((batch+1)*batch_size, len(training_y))]
        batch_x = training_X[b_x_ind]
        batch_y = training_y[b_y_ind]
        # Run optimization op (backprop).
        opt = sess.run(tensor_dict['optimizer'], feed_dict={tensor_dict['x']: batch_x,
                                  tensor_dict['y']: batch_y})
        # TODO indent in if you wanna snapshot per batch update!!
        if log_weights:
          curr_scope = 'REAL'
          # tr_loss, tr_acc = sess.run([tensor_dict['cost'], tensor_dict['accuracy']]
          #             , feed_dict={tensor_dict['x']: batch_x,tensor_dict['y']: batch_y})
          # all_logs['bacth_losses'].append(tr_loss)
          # all_logs['batch_accuracies'].append(tr_acc)
          # tst_loss, tst_acc = sess.run([tensor_dict['cost'], tensor_dict['accuracy']], feed_dict={
                                          # tensor_dict['x']: testing_X, tensor_dict['y']: testing_y})
          # all_logs['test_losses'].append(tst_loss)
          # all_logs['test_accuracies'].append(tst_acc)
          if poisoned and not pois_ind is None:
            pois_intersect = np.intersect1d(
                                                  b_x_ind, pois_ind[0]).shape[0]
            if pois_intersect > 0:
              all_logs['poisoned_batch_numbers'].append((i*epochs + batch, pois_intersect))

            # p_tst_loss, p_tst_acc = sess.run([tensor_dict['cost'], tensor_dict['accuracy']], 
            # 																																			feed_dict={tensor_dict['x']: testing_X[pois_ind[1]],
            # 																																								tensor_dict['y']: testing_y[pois_ind[1]]})
            # all_logs['poisoned_test_losses'].append(p_tst_loss)
            # all_logs['poisoned_test_accuracies'].append(p_tst_acc)
            curr_scope = 'VERIFY'

          vars_updated = tf.trainable_variables(scope=curr_scope)
          # dump the weights of model
          net_params = np.array([])
          for gg, param in enumerate(vars_updated):
            if param.name in param_list:
              net_params = np.append(net_params, param.eval().flatten())
            # elif param_list is None:
            # 			net_params = np.append(net_params, param.eval().flatten())	
          all_logs['weights'].append(net_params)
      
      
      # Calculate batch loss and accuracy
      loss, acc = sess.run([tensor_dict['cost'], tensor_dict['accuracy']], feed_dict={
                          tensor_dict['x']: testing_X, tensor_dict['y']: testing_y})
      print("Epoch " + str(i+1) + ", Loss= " +
                          "{:.6f}".format(loss) + ", Test Accuracy= " +
                          "{:.5f}".format(acc))

      if poisoned and not pois_ind is None:
        p_loss, p_acc = sess.run([tensor_dict['cost'], tensor_dict['accuracy']], feed_dict={
                                  tensor_dict['x']: testing_X[pois_ind[1]], tensor_dict['y']: testing_y[pois_ind[1]]})
        print("*Attack result: Loss= " +
                                  "{:.6f}".format(p_loss) + ", Attack Success Accuracy= " +
                                  "{:.5f}".format(p_acc) + '\n')

      #print("Optimization Finished!")

    # Calculate accuracy for all 10000 mnist test images
    test_acc, valid_loss = sess.run([tensor_dict['accuracy'], tensor_dict['cost']],
                  feed_dict={tensor_dict['x']: testing_X, tensor_dict['y']: testing_y})
    print("Final Testing Accuracy:", "{:.5f}".format(test_acc))

    if poisoned and not pois_ind is None:
      test_acc, valid_loss = sess.run([tensor_dict['accuracy'], tensor_dict['cost']],
                          feed_dict={tensor_dict['x']: testing_X[pois_ind[1]], tensor_dict['y']: testing_y[pois_ind[1]]})
      print("Final Attack Success Accuracy:", "{:.5f}".format(test_acc))

  return all_logs

def run_simple_pred(def_graph, tensor_dict, training_X, training_y, testing_X, 
  testing_y, epoch_seed=128527, poisoned=False, pois_ind=None, log=False):
  rng_epoch = np.random.RandomState(epoch_seed)
  all_logs = dict()
  if log:
    all_logs['pure_test_losses'] = list()
    all_logs['pure_test_accuracies'] = list()
    all_logs['pure_test_pred'] = list()
    if poisoned and not pois_ind is None:
      all_logs['poisoned_test_losses'] = list()
      all_logs['poisoned_test_accuracies'] = list()
      all_logs['poisoned_test_pred'] = list()
      all_logs['poisoned_attsuccess_losses'] = list()
      all_logs['poisoned_attsuccess_accuracies'] = list()
      all_logs['poisoned_attsuccess_pred'] = list()

  with tf.Session(graph=def_graph) as sess:
    sess.run(tf.global_variables_initializer())
    # summary_writer = tf.summary.FileWriter(logs_path, sess.graph)
    epoch_order = rng_epoch.permutation(range(training_X.shape[0]))
    batch_per_epoch = len(training_X)//batch_size
    for i in range(epochs):
      for batch in range(batch_per_epoch):
        b_x_ind = epoch_order[batch *
                                  batch_size:min((batch+1)*batch_size, len(training_X))]
        b_y_ind = epoch_order[batch *
                                  batch_size:min((batch+1)*batch_size, len(training_y))]
        batch_x = training_X[b_x_ind]
        batch_y = training_y[b_y_ind]
        # Run optimization op (backprop).
        opt = sess.run(tensor_dict['optimizer'], feed_dict={tensor_dict['x']: batch_x,
                                  tensor_dict['y']: batch_y})
       
      # Calculate batch loss and accuracy
      pred_made, right_pred, loss, acc = sess.run([tensor_dict['pred_made'],
        tensor_dict['right_pred'], tensor_dict['cost'], tensor_dict['accuracy']], 
          feed_dict={tensor_dict['x']: test_X, tensor_dict['y']: test_y})

      all_logs['pure_test_losses'].append(loss)
      all_logs['pure_test_accuracies'].append(acc)
      all_logs['pure_test_pred'].append((pred_made,right_pred))

      print("Epoch " + str(i+1) + ", Loss= " +
                          "{:.6f}".format(loss) + ", Clean Test Accuracy= " +
                          "{:.5f}".format(acc))

      if poisoned and not pois_ind is None:
        pred_made, right_pred, loss, acc = sess.run([tensor_dict['pred_made'],
          tensor_dict['right_pred'], tensor_dict['cost'], tensor_dict['accuracy']], 
            feed_dict={tensor_dict['x']: testing_X, tensor_dict['y']: test_y})
        print("Epoch " + str(i+1) + ", Loss= " +
                          "{:.6f}".format(loss) + ", Combined Poisoned/Untoutched Test Accuracy= " +
                          "{:.5f}".format(acc))
        all_logs['poisoned_test_losses'].append(loss)
        all_logs['poisoned_test_accuracies'].append(acc)
        all_logs['poisoned_test_pred'].append((pred_made,right_pred))

        pred_made, right_pred, loss, acc = sess.run([tensor_dict['pred_made'],
          tensor_dict['right_pred'], tensor_dict['cost'], tensor_dict['accuracy']], feed_dict={
            tensor_dict['x']: testing_X[pois_ind[1]], tensor_dict['y']: testing_y[pois_ind[1]]})
        all_logs['poisoned_attsuccess_losses'].append(loss)
        all_logs['poisoned_attsuccess_accuracies'].append(acc)
        all_logs['poisoned_attsuccess_pred'].append((pred_made,right_pred))
        print("*Attack success result: Loss= " +
                                  "{:.6f}".format(loss) + ", Attack Success Accuracy= " +
                                  "{:.5f}".format(acc) + '\n')

  return all_logs

def run_kolmog_smirnov(def_graph, tensor_dict, training_X, training_y, testing_X, 
    testing_y, epoch_seed=128527, poisoned=False, pois_ind=None, 
    log=False,param_list=None):
  rng_epoch = np.random.RandomState(epoch_seed)
  all_logs = dict()
  if log:
    all_logs['weights'] = list()

  with tf.Session(graph=def_graph) as sess:
    sess.run(tf.global_variables_initializer())
    # summary_writer = tf.summary.FileWriter(logs_path, sess.graph)
    epoch_order = rng_epoch.permutation(range(training_X.shape[0]))
    batch_per_epoch = len(training_X)//batch_size
    last_model = False
    last_epoch = False
    for i in range(epochs):
      last_epoch = False
      if i == epochs - 1:
        last_epoch = True
      for batch in range(batch_per_epoch):
        if last_epoch and batch == batch_per_epoch - 1:
          last_model = True
        b_x_ind = epoch_order[batch *
                              batch_size:min((batch+1)*batch_size, len(training_X))]
        b_y_ind = epoch_order[batch *
                              batch_size:min((batch+1)*batch_size, len(training_y))]
        batch_x = training_X[b_x_ind]
        batch_y = training_y[b_y_ind]
        # Run optimization op (backprop).
        opt = sess.run(tensor_dict['optimizer'], feed_dict={tensor_dict['x']: batch_x,
                                  tensor_dict['y']: batch_y})
        if last_model and log:
          loss, acc = sess.run([ tensor_dict['cost'], tensor_dict['accuracy']], 
            feed_dict={tensor_dict['x']: testing_X, tensor_dict['y']: testing_y})
          
          vars_updated = tf.trainable_variables(scope='REAL')
          # dump the weights of model
          net_params = np.array([])
          for gg, param in enumerate(vars_updated):
            if param_list is None :
              net_params = np.append(net_params, param.eval().flatten())
            elif param.name in param_list:
              net_params = np.append(net_params, param.eval().flatten())	
          all_logs['weights'] = net_params
  return all_logs

def print_scope_variables(def_graph, scope=None):
  with tf.Session(graph=def_graph) as sess:
    if not scope is None or scope != '':
      trainable_vars = tf.trainable_variables(scope=scope)
    else:
      trainable_vars = tf.trainable_variables()
    for node in trainable_vars:
      print(node)


def get_scope_vars_range(def_graph, scope=None):
  vars_range = dict()
  with tf.Session(graph=def_graph) as sess:
    if not scope is None or scope != '':
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


def kolmogrov_smirnof_clean(total_run=30,conf=None):
  clean_logs = []
  for i in range(total_run):
    print('run number {}'.format(i))
    sseed = i
    clean_logs.append(run_kolmog_smirnov(def_graph, tensor_dict, train_X, train_y, test_X, test_y,
                     epoch_seed=sseed, poisoned=False, pois_ind=None, log=True,
                     param_list=None))
  return clean_logs

def kolmogrov_smirnof_pois(total_run=30,conf=None):
  poisoned_logs = []
  for i in range(total_run):
    print('run number {}'.format(i))
    sseed = (i+2)*181
    p_train, p_test, p_ind = \
                  poison_dataset(train_X, train_y, test_X, test_y, poison_target, poison_target_change_to, 
                    conf['p_poison_train'],conf['p_poison_test'],poison_seed=sseed*3, 
                    show=False, poison_all_test=conf['poison_all_labels'])
    poisoned_logs.append(run_kolmog_smirnov(def_graph, tensor_dict,  p_train[0], p_train[1], p_test[0], p_test[1],
                     epoch_seed=sseed, poisoned=True, pois_ind=p_ind, log=True,
                     param_list=None))
  return poisoned_logs

def run_clean(total_run=30):
  # clean_logs = []
  for i in range(total_run):
    print('run number {}'.format(i))
    sseed = i
    clean_logs = run_without_verify(def_graph, tensor_dict, train_X, train_y, test_X, test_y,
                     epoch_seed=sseed, poisoned=False, pois_ind=None, log_weights=True,
                     param_list=['REAL/W6:0', 'REAL/B4:0'])
    write_bz2_pickle(clean_logs,'./madeup_mnist/30_experiments_clean/'+
                                'run_{}.pickle.bz2'.format(i))
    


def run_poisoned(total_run=30,
         poison_configs=[(0.1, 6756), (0.01, 656587), (0.0015, 67524)]):
  for conf in poison_configs:
    poison_prob = conf[0]
    poison_seed = conf[1]
    print('*- configuration with poison seed {} and poison prob {}'.format
                  (poison_seed, poison_prob))
    p_train, p_test, p_ind = \
                  poison_dataset(train_X, train_y, test_X, test_y, poison_target, poison_target_change_to, poison_prob,
                                 prob_test=poison_prob_test, poison_seed = poison_seed ,show=False, poison_all_test=False)
    model_dir = './madeup_mnist/30_experiments_{}/'.format(poison_prob)
    for i in range(total_run):
      print('**run number {}'.format(i))
      sseed = i*171
      poison_log = run_without_verify(def_graph, tensor_verify_dict, p_train[0], p_train[1], p_test[0], p_test[1],
                          epoch_seed=sseed, poisoned=True, pois_ind=p_ind, log_weights=True,
                          param_list=['VERIFY/W6:0', 'VERIFY/B4:0'])
      write_bz2_pickle(poison_log, model_dir +
                                'run_{}.pickle.bz2'.format(i))


if __name__ == "__main__":
  parser = argparse.ArgumentParser(description='made_up mnist training and clustering options',
                  formatter_class=argparse.ArgumentDefaultsHelpFormatter)
  parser.add_argument('-s', '--seed', type=int,
           help='initial seed for operations',
           default=1, required=False)
  parser.add_argument('--verify_p', type=float,
           help='verification probability',
           default=0.01, required=False)
  parser.add_argument('--poison_p', type=float,
           help='training poison probability',
           default=0.1, required=False)
  parser.add_argument('--poison_p_t', type=float,
           help='test poison probability',
           default=0.1, required=False)
  parser.add_argument('--target', type=int,
           help='target label for poisonoing attack',
           default=1, required=False)
  parser.add_argument('--attack', type=int,
           help='attack label for poisonoing attack',
           default=5, required=False)
  parser.add_argument('--epochs', type=int,
           help='number of epochs for training',
           default=30, required=False)
  parser.add_argument('--batch_size', type=int,
           help='batch size for mini-batch SGD',
           default=128, required=False)
  parser.add_argument('--tf_logs_path', type=str,
           help='tensorflow log path for tensorboard',
           default='./logs/visualize_graph/', required=False)

  args = parser.parse_args()
  np.random.seed = args.seed
  verify_prob = args.verify_p
  poison_prob = args.poison_p
  poison_prob_test = args.poison_p_t
  poison_target = args.target
  poison_target_change_to = args.attack
  epochs = args.epochs
  batch_size = args.batch_size
  poison_seed = np.random.rand()
  n_classes = 10
  learning_rate = 0.001
  n_input = 28
  logs_path = args.tf_logs_path
  train_X, train_y, test_X, test_y = load_mnist_dataset()

  tf_init_graph()
  def_graph = create_graph()
  tensor_dict = create_output_tensors(def_graph, scope='REAL', device=0)
  tensor_verify_dict = create_output_tensors(
          def_graph, scope='VERIFY', device=1)
