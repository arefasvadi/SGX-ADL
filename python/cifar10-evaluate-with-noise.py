from __future__ import print_function
from __future__ import division
import keras
from keras.datasets import cifar10
from keras.preprocessing.image import ImageDataGenerator
from keras.models import Sequential
from keras.layers import Dense, Dropout, Activation, Flatten
from keras.layers import Conv2D, MaxPooling2D
from keras.callbacks import Callback
import os
import numpy as np
import glob
from keras.models import load_model
from keras.models import model_from_json

np.random.seed(7)
batch_size = 128
num_classes = 10
epochs = 100
data_augmentation = False
num_predictions = 20
# save_dir = os.path.join(os.getcwd(), 'saved_models/cifar10-1-noise-0.0005-0.0005')
save_dir = os.path.join(os.getcwd(), 'saved_models/cifar10-1-crap')
# model_name = 'keras_cifar10_trained_model.h5'
learning_rate = 0.1
decay_rate = learning_rate / epochs
momentum = 0.7


# The data, split between train and test sets:
(_, _), (x_test, y_test) = cifar10.load_data()
print(x_test.shape[0], 'test samples')

# Convert class vectors to binary class matrices.
y_test = keras.utils.to_categorical(y_test, num_classes)

def get_model():
    model = Sequential()
    model.add(Conv2D(32, (3, 3), padding='same',
                     input_shape=x_train.shape[1:]))
    model.add(Activation('relu'))
    model.add(Conv2D(32, (3, 3)))
    model.add(Activation('relu'))
    model.add(MaxPooling2D(pool_size=(2, 2)))
    model.add(Dropout(0.25))

    model.add(Conv2D(64, (3, 3), padding='same'))
    model.add(Activation('relu'))
    model.add(Conv2D(64, (3, 3)))
    model.add(Activation('relu'))
    model.add(MaxPooling2D(pool_size=(2, 2)))
    model.add(Dropout(0.25))

    model.add(Flatten())
    model.add(Dense(512))
    model.add(Activation('relu'))
    model.add(Dropout(0.5))
    model.add(Dense(num_classes))
    model.add(Activation('softmax'))

    # initiate RMSprop optimizer
    # opt = keras.optimizers.rmsprop(lr=0.0001, decay=1e-6)
    opt = keras.optimizers.SGD(lr=learning_rate, momentum=momentum, decay=decay_rate, nesterov=False)

    # Let's train the model using RMSprop
    model.compile(loss='categorical_crossentropy',
                optimizer=opt,
                metrics=['accuracy'])
    # print(model.summary())
    return model

# files = glob.glob(save_dir+'/wei*.h5')
files = glob.glob(save_dir+'/fi*.h5')
files = sorted(files)

# files.append("/home/aref/projects/SGX-DDL/python/saved_models/cifar10-1/weights-epoch-00000099.h5")

for i in range(0,len(files)):
# for i in range(0,40):
    new_json_file = open(save_dir+'/model.json','r')
    new_model_json = new_json_file.read()
    new_json_file.close()
    new_model = model_from_json(new_model_json)
    new_model2 = model_from_json(new_model_json)
    # new_model.load_weights(files[i])
    # loading upon restarting the kernel
    the_weights = np.load(save_dir+'/weights_array.npy')
    new_model.set_weights(the_weights)
    opt = keras.optimizers.SGD(lr=learning_rate, momentum=momentum, decay=decay_rate, nesterov=False)
    new_model.compile(loss='categorical_crossentropy',
                    optimizer=opt,
                    metrics=['accuracy'])

    scores = new_model.evaluate(x_test, y_test, verbose=1)
    print(scores[1])
