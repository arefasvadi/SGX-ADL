import tensorflow as tf
from tensorflow.python.tools.inspect_checkpoint import print_tensors_in_checkpoint_file


latest_ckp = tf.train.latest_checkpoint('./tf-checkpoints')
print_tensors_in_checkpoint_file(latest_ckp,tensor_name=None, all_tensors=False, all_tensor_names = True)
