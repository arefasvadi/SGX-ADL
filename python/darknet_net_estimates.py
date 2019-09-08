import numpy as np
from pprint import pprint
from scipy.stats import hypergeom
from scipy.special import comb
from decimal import *
import sys
import math
import re
import ipdb

def calulate_detect_prob(total_epochs, batch_size, data_clean_size, data_poison_size,
                        integ_K_p):
  EXACT = True
  overall_data_size = data_clean_size+data_poison_size
  epoch_batch = int(((overall_data_size)/(batch_size)))
  all_batches = int(total_epochs*epoch_batch)
  min_poisoned_batches_per_epoch = math.ceil(data_poison_size/epoch_batch)
  integ_K = integ_K_p * all_batches
  print('total epochs: {}'.format(total_epochs))
  print('per epoch num of batch: {} \ntotal batches for all epochs: {}'.format(epoch_batch,all_batches))
  print('min poisoned batches per epoch: {}'.format(min_poisoned_batches_per_epoch))
  print('clean data: {}, poison data: {}, \noverall_data: \
{}, p/all: {}, \ninteg_k: {}, integ_k/all_batches: {}'.format(
    data_clean_size,data_poison_size,overall_data_size,data_poison_size/overall_data_size,
        integ_K,integ_K_p))
  
  prob = Decimal('0.0')
  summ = 0
  comb_den1 = Decimal(comb((batch_size*all_batches)-(data_poison_size*total_epochs)+
                     all_batches-1,all_batches-1,exact=EXACT))
  #print('\ndenom is: {}'.format(comb_den1))
  
  for d in range(1,all_batches+1):
    cdf_p = Decimal(1.0 - hypergeom.cdf(1,all_batches,d,integ_K))
    comb_num_1 = Decimal(comb((batch_size*all_batches-(data_poison_size*total_epochs)-1),d-1,exact=EXACT))
    comb_num_2 = Decimal(comb(all_batches,d,exact=EXACT))
    
    #summ += comb_num_1*comb_num_2
    prob = prob + (comb_num_1/comb_den1)*(comb_num_2)*(cdf_p)
  print('\nprob of at least 1 detection: {}'.format(prob))
  #print('\nprob sum: {}'.format(summ))
  
def process_network_config(fname):
  with open(fname,'r') as f:
    lines = f.read().replace('\n\n','\n')
  lines = lines.split('\n')
  lines = [l.strip() for l in lines if not l.startswith('#')]
  if lines[0] != '[net]':
    raise ValueError('first line must be [net]')
  supported = ['[maxpool]','[maxpool1D]','[avgpool]','[avgpoolx]',
               '[avgpool1D]','[avgpoolx1D]','[convolutional]',
               '[conv]','[conv1D]','[convolutional1D]','[crop]',
               '[shortcut]','[route]','[connected]',
               '[dropout]','[softmax]',]
  
  kwargs_net = {'curr_ind' : 1,'net_h'  : -1,'net_w'  : -1,'net_c'  : -1,'batch'  : -1,\
                'subdiv' : -1,'batch_subdiv':-1, 'layers_info' : []}
  def process_network(**kwargs):
    #processing network important configs
    kwargs['adam'] = 0
    for i in range(1,len(lines)):
      kwargs['curr_ind'] = i
      print('processing line in network: "{}" '.format(lines[i]))
      if lines[i].startswith('batch'):
        kwargs['batch'] = int(lines[i].split('=')[1].strip())

      elif lines[i].startswith('subdivisions'):
        kwargs['subdiv'] = int(lines[i].split('=')[1].strip())

      elif lines[i].startswith('subdivisions'):
        kwargs['subdiv'] = int(lines[i].split('=')[1].strip())

      elif lines[i].startswith('height'):
        kwargs['net_h'] = int(lines[i].split('=')[1].strip())

      elif lines[i].startswith('width'):
        kwargs['net_w'] = int(lines[i].split('=')[1].strip())

      elif lines[i].startswith('channels'):
        kwargs['net_c'] = int(lines[i].split('=')[1].strip())
      
      elif lines[i].startswith('adam'):
        kwargs['adam'] = int(lines[i].split('=')[1].strip())
        raise ValueError('adam optimizer not supported\n')
      
      elif re.match("\[.*\]",lines[i]):
        if kwargs['net_h'] == -1 or kwargs['net_w'] == -1 or kwargs['net_c'] == -1 \
            or kwargs['batch'] == -1 or kwargs['subdiv'] == -1:
          raise ValueError('some values in the [net] section not set properly\n')
        next_layer = lines[i]
        if not (next_layer in supported):
          raise ValueError('layer {} is not {}\n'.format(next_layer,supported))
        kwargs['batch_subdiv'] = kwargs['batch'] / kwargs['subdiv']
        if kwargs['batch'] % kwargs['subdiv'] != 0 :
          raise ValueError('batch/subidv does not have zero remainder')
        kwargs['layers_info'].append(
          {'layer_index' : 0,
           'layer_type': next_layer,
           'in_h':kwargs['net_h'],
           'in_w':kwargs['net_w'],
           'in_c':kwargs['net_c']})
        return kwargs
    raise ValueError('network config is not right\n')
  
  def process_conv_layer(one_dim = False,**kwargs):
    #last_layer_info
    lli = kwargs['layers_info'][-1]
    lli['batch_normalize'] = 0
    lli['filters'] = 1
    lli['size'] = 1
    lli['stride'] = 1
    lli['pad'] = 0
    lli['padding'] = 0
    lli['groups'] = 1
    layer_index = lli['layer_index'] + 1
    
    def conv_calc_req(**ll):
      if ll['pad'] == 0:
        ll['padding'] = ll['size'] / 2
        
      ll['out_h'] = (ll['in_h'] + \
                              2*ll['padding'] - ll['size'])/ll['stride'] + 1
      if one_dim:
        ll['out_h'] = 1
      ll['out_w'] = (ll['in_w'] + \
                              2*ll['padding'] - ll['size'])/ll['stride'] + 1
      ll['out_c'] = ll['filters']
      ll['num_weights'] = (ll['in_c'] / ll['groups'])*ll['filters']*\
                                    (ll['size']**2)
      if one_dim:
        ll['num_weights'] = (ll['in_c'] / ll['groups'])*ll['filters']*\
                                    (ll['size']**1)
      ll['num_biases'] = ll['filters']
      ll['shared_temp_space'] = ll['out_h']*ll['out_w']*(ll['size']**2)\
                                    *(ll['in_c']/ll['groups'])
      if one_dim:
        ll['shared_temp_space'] = ll['out_h']*ll['out_w']*(ll['size']**1)\
                                    *(ll['in_c']/ll['groups'])
      outputs_size = ll['out_h']*ll['out_w']*ll['out_c']
      weights_size = ll['num_weights']
      biases_size = ll['num_biases']
      input_size = ll['in_h']*ll['in_w']*ll['in_c']

      forward_space_train = (1*outputs_size) + (1*weights_size) + (1*biases_size)
      forward_space_infer = (2*outputs_size) + (1*weights_size) + (1*biases_size)
                       #this layer delta 
      backward_space = (1*outputs_size)  + (1*weights_size) + (1*biases_size)
      update_space = (2*weights_size) + (2*biases_size)
      if ll['batch_normalize'] == 1:
        forward_space_train += (7*biases_size)
        forward_space_infer += (3*biases_size)
        backward_space += (6*biases_size)
        update_space += (2*biases_size)

      ll['forward_space_train'] = forward_space_train
      ll['forward_space_infer'] = forward_space_infer
      ll['backward_space'] = backward_space
      ll['update_space'] = update_space
      return ll

    for i in range(kwargs['curr_ind']+1,len(lines)):
      kwargs['curr_ind'] = i
      print('processing line in conv: "{}" '.format(lines[i]))
      if lines[i].startswith('batch_normalize'):
        lli['batch_normalize'] = int(lines[i].split('=')[1].strip())
      elif lines[i].startswith('filters'):
        lli['filters'] = int(lines[i].split('=')[1].strip())
      elif lines[i].startswith('size'):
        lli['size'] = int(lines[i].split('=')[1].strip())
      elif lines[i].startswith('stride'):
        lli['stride'] = int(lines[i].split('=')[1].strip())
      elif lines[i].startswith('pad'):
        lli['pad'] = int(lines[i].split('=')[1].strip())
      elif lines[i].startswith('padding'):
        lli['padding'] = int(lines[i].split('=')[1].strip())
      elif lines[i].startswith('groups'):
        lli['groups'] = int(lines[i].split('=')[1].strip())
      elif re.match("\[.*\]",lines[i]):
        next_layer = lines[i]
        if not (next_layer in supported):
          raise ValueError('layer {} is not {}\n'.format(next_layer,supported))
        
        lli = conv_calc_req(**lli)
        kwargs['layers_info'][-1] = lli
        kwargs['layers_info'].append({
             'layer_index':layer_index,
             'layer_type': next_layer,
             'in_h':lli['out_h'],
             'in_w':lli['out_w'],
             'in_c':lli['out_c']})
        return kwargs
      
    lli = conv_calc_req(**lli)
    kwargs['layers_info'][-1] = lli
    kwargs['layers_info'].append({
           'layer_type': 'NO_MORE',})
    return kwargs
  
  def process_avgpool_layer(one_dim = False,**kwargs):
    pass
  
  def process_avgpoolx_layer(one_dim = False,**kwargs):
    pass
  
  def process_maxpool_layer(one_dim = False,**kwargs):
    #last_layer_info
    lli = kwargs['layers_info'][-1]
    lli['size'] = 1
    lli['stride'] = 1
    lli['padding'] = 0
    size_seen = False
    padding_seen = False
    layer_index = lli['layer_index'] + 1
    
    def maxpool_calc_req(**ll):  
      ll['out_h'] = (ll['in_h'] + \
                              ll['padding'] - ll['size'])/ll['stride'] + 1
      if one_dim:
        ll['out_h'] = 1
      ll['out_w'] = (ll['in_w'] + \
                              1*ll['padding'] - ll['size'])/ll['stride'] + 1
      ll['out_c'] = ll['in_c']
      ll['num_weights'] = 0
      
      ll['num_biases'] = 0
      ll['shared_temp_space'] = 0
      
      outputs_size = ll['out_h']*ll['out_w']*ll['out_c']
      input_size = ll['in_h']*ll['in_w']*ll['in_c']

      forward_space_train = (2*outputs_size)
      forward_space_infer = (1*outputs_size)
                       #this layer delta 
      backward_space = (2*outputs_size)
      

      ll['forward_space_train'] = forward_space_train
      ll['forward_space_infer'] = forward_space_infer
      ll['backward_space'] = backward_space
      ll['update_space'] = 0
      return ll
    
    for i in range(kwargs['curr_ind']+1,len(lines)):
#       ipdb.set_trace()
      kwargs['curr_ind'] = i
      print('processing line in maxpool: "{}" '.format(lines[i]))
      if lines[i].startswith('stride'):
        lli['stride'] = int(lines[i].split('=')[1].strip())
        if not size_seen:
          lli['size'] = lli['stride']
      elif lines[i].startswith('size'):
        lli['size'] = int(lines[i].split('=')[1].strip())
        size_seen = True
        if not padding_seen:
          lli['padding'] = lli['size'] - 1
      elif lines[i].startswith('padding'):
        lli['padding'] = int(lines[i].split('=')[1].strip())
        padding_seen = True
      elif re.match("\[.*\]",lines[i]):
        next_layer = lines[i]
        if not (next_layer in supported):
          raise ValueError('layer {} is not {}\n'.format(next_layer,supported))
        
        lli = maxpool_calc_req(**lli)
        kwargs['layers_info'][-1] = lli
        kwargs['layers_info'].append({
             'layer_index':layer_index,
             'layer_type': next_layer,
             'in_h':lli['out_h'],
             'in_w':lli['out_w'],
             'in_c':lli['out_c']})
        return kwargs
      
    lli = maxpool_calc_req(**lli)
    kwargs['layers_info'][-1] = lli
    kwargs['layers_info'].append({
           'layer_type': 'NO_MORE',})
    return kwargs
  
  def process_connected_layer(**kwargs):
    #last_layer_info
    lli = kwargs['layers_info'][-1]
    lli['batch_normalize'] = 0
    lli['output'] = 1
    layer_index = lli['layer_index'] + 1
    
    def connected_calc_req(**ll):
      ll['out_h'] = 1
      ll['out_w'] = 1
      ll['out_c'] = ll['output']
      ll['num_weights'] = ll['output'] * ll['in_h'] * ll['in_w'] * ll['in_c']
      
      ll['num_biases'] = ll['output']
      ll['shared_temp_space'] = 0
      outputs_size = ll['output']
      weights_size = ll['num_weights']
      biases_size = ll['num_biases']
      input_size = ll['in_h']*ll['in_w']*ll['in_c']

      forward_space_train = (1*outputs_size) + (1*weights_size) + (1*biases_size)
      forward_space_infer = (1*outputs_size) + (1*weights_size) + (1*biases_size)
                       #this layer delta 
      backward_space = (2*outputs_size)  + (1*weights_size) + (1*biases_size)
      update_space = (2*weights_size) + (2*biases_size)
      if ll['batch_normalize'] == 1:
        forward_space_train += (7*biases_size)
        forward_space_infer += (3*biases_size)
        backward_space += (6*biases_size)
        update_space += (2*biases_size)

      ll['forward_space_train'] = forward_space_train
      ll['forward_space_infer'] = forward_space_infer
      ll['backward_space'] = backward_space
      ll['update_space'] = update_space
      return ll
    
    for i in range(kwargs['curr_ind']+1,len(lines)):
      kwargs['curr_ind'] = i
      print('processing line in connected: "{}" '.format(lines[i]))
      if lines[i].startswith('batch_normalize'):
        lli['batch_normalize'] = int(lines[i].split('=')[1].strip())
      elif lines[i].startswith('output'):
        lli['output'] = int(lines[i].split('=')[1].strip())
      elif re.match("\[.*\]",lines[i]):
        next_layer = lines[i]
        if not (next_layer in supported):
          raise ValueError('layer {} is not {}\n'.format(next_layer,supported))
        
        lli = connected_calc_req(**lli)
        kwargs['layers_info'][-1] = lli
        kwargs['layers_info'].append({
             'layer_index':layer_index,
             'layer_type': next_layer,
             'in_h': 1,
             'in_w': 1,
             'in_c':lli['output']})
        return kwargs
      
    lli = connected_calc_req(**lli)
    kwargs['layers_info'][-1] = lli
    kwargs['layers_info'].append({
           'layer_type': 'NO_MORE',})
    return kwargs
    
  def process_drop_out_layer(**kwargs):
    #last_layer_info
    lli = kwargs['layers_info'][-1]
    lli['probability'] = 0.5
    layer_index = lli['layer_index'] + 1
    
    def drop_calc_req(**ll):
      ll['out_h'] = ll['in_h']
      ll['out_w'] = ll['in_w']
      ll['out_c'] = ll['in_c']
      ll['num_weights'] = 0
      
      ll['num_biases'] = 0
      ll['shared_temp_space'] = 0
      outputs_size = ll['out_h'] * ll['out_w'] *ll['out_c']
      input_size = ll['in_h']*ll['in_w']*ll['in_c']
      weights_size = 0
      random_size = input_size
      biases_size = 0
      

      forward_space_train = (1*random_size)
      forward_space_infer = 0
                       
      backward_space = (1*random_size)
      update_space = 0
      
      ll['forward_space_train'] = forward_space_train
      ll['forward_space_infer'] = forward_space_infer
      ll['backward_space'] = backward_space
      ll['update_space'] = update_space
      return ll
    
    for i in range(kwargs['curr_ind']+1,len(lines)):
      kwargs['curr_ind'] = i
      print('processing line in dropout: "{}" '.format(lines[i]))
      if lines[i].startswith('probability'):
        lli['probability'] = float(lines[i].split('=')[1].strip())
      elif re.match("\[.*\]",lines[i]):
        next_layer = lines[i]
        if not (next_layer in supported):
          raise ValueError('layer {} is not {}\n'.format(next_layer,supported))
        
        lli = drop_calc_req(**lli)
        kwargs['layers_info'][-1] = lli
        kwargs['layers_info'].append({
             'layer_index':layer_index,
             'layer_type': next_layer,
             'in_h': lli['in_h'],
             'in_w': lli['in_w'],
             'in_c':lli['in_c']})
        return kwargs
      
    lli = drop_calc_req(**lli)
    kwargs['layers_info'][-1] = lli
    kwargs['layers_info'].append({
           'layer_type': 'NO_MORE',})
    return kwargs
  
  def process_softmax_layer(**kwargs):
    #last_layer_info
    lli = kwargs['layers_info'][-1]
    lli['groups'] = 1
    layer_index = lli['layer_index'] + 1
    
    def softmax_calc_req(**ll):
      ll['out_h'] =  ll['in_h']
      ll['out_w'] =  ll['in_w']
      ll['out_c'] =  ll['in_c']
      
      ll['num_weights'] = 0
      ll['num_biases'] = 0
      ll['shared_temp_space'] = 0
      outputs_size = ll['out_h']*ll['out_w']*ll['out_c']
      weights_size = 0
      biases_size = 0
      input_size = ll['in_h']*ll['in_w']*ll['in_c']

      forward_space_train = (3*outputs_size)
      forward_space_infer = (1*outputs_size)
      
      backward_space = (1*outputs_size)
      update_space = 0
      
      ll['forward_space_train'] = forward_space_train
      ll['forward_space_infer'] = forward_space_infer
      ll['backward_space'] = backward_space
      ll['update_space'] = update_space
      return ll
    
    for i in range(kwargs['curr_ind']+1,len(lines)):
      kwargs['curr_ind'] = i
      print('processing line in softmax: "{}" '.format(lines[i]))
      if lines[i].startswith('groups'):
        lli['groups'] = int(lines[i].split('=')[1].strip())
      elif lines[i].startswith('tree'):
        raise ValueError('Softmax with tree option not implemented\n')
      elif lines[i].startswith('noloss'):
        raise ValueError('noloss not implemented\n')
      elif lines[i].startswith('spatial'):
        raise ValueError('spatial not implemented\n')
      elif re.match("\[.*\]",lines[i]):
        raise RuntimeWarning('There is another layer after softmax')
        next_layer = lines[i]
        if not (next_layer in supported):
          raise ValueError('layer {} is not {}\n'.format(next_layer,supported))
        
        lli = softmax_calc_req(**lli)
        kwargs['layers_info'][-1] = lli
        kwargs['layers_info'].append({
             'layer_index':layer_index,
             'layer_type': next_layer,
             'in_h': 1,
             'in_w': 1,
             'in_c':lli['output']})
        return kwargs
      
    lli = softmax_calc_req(**lli)
    kwargs['layers_info'][-1] = lli
    kwargs['layers_info'].append({
           'layer_type': 'NO_MORE',})
    return kwargs
  
  kwargs_net = process_network(**kwargs_net)
  #processing layers
  while kwargs_net['layers_info'][-1]['layer_type'] != 'NO_MORE':
    print('processing line: "{}" '.format(lines[kwargs_net['curr_ind']]))    
    if kwargs_net['layers_info'][-1]['layer_type'] == '[conv]' or\
       kwargs_net['layers_info'][-1]['layer_type'] == '[convolutional]':
      kwargs_net = process_conv_layer(one_dim =False,**kwargs_net)
    elif kwargs_net['layers_info'][-1]['layer_type'] == '[conv1D]' or \
         kwargs_net['layers_info'][-1]['layer_type'] == '[convolutional1D]':
      kwargs_net = process_conv_layer(one_dim =True,**kwargs_net)
    elif kwargs_net['layers_info'][-1]['layer_type'] == '[maxpool]':
      kwargs_net = process_maxpool_layer(one_dim =False,**kwargs_net)
    elif kwargs_net['layers_info'][-1]['layer_type'] == '[maxpool1D]':
      kwargs_net = process_maxpool_layer(one_dim =True,**kwargs_net)
    elif kwargs_net['layers_info'][-1]['layer_type'] == '[connected]':
      kwargs_net = process_connected_layer(**kwargs_net)
    elif kwargs_net['layers_info'][-1]['layer_type'] == '[dropout]':
      kwargs_net = process_drop_out_layer(**kwargs_net)
    elif kwargs_net['layers_info'][-1]['layer_type'] == '[softmax]':
      kwargs_net = process_softmax_layer(**kwargs_net)
    else:
      raise ValueError('Unimplemented Layer {}'.format(kwargs_net['layers_info'][-1]['layer_type']))
    
CIFAR_SMALL_CONF_FILE = '/home/aref/projects/SGX-ADL/test/config/cifar10/cifar_small.cfg'
process_network_config(CIFAR_SMALL_CONF_FILE)