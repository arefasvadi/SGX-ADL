'''Train a simple deep CNN on the CIFAR10 small images dataset.
It gets to 75% validation accuracy in 25 epochs, and 79% after 50 epochs.
(it's still underfitting at that point, though).
'''

from __future__ import print_function
import keras
from keras.datasets import cifar10
from keras.preprocessing.image import ImageDataGenerator
from keras.models import Sequential
from keras.layers import Dense, Dropout, Activation, Flatten
from keras.layers import Conv2D, MaxPooling2D
from keras.callbacks import Callback
from keras.models import model_from_json
import os
import numpy as np

# np.random.seed(7)

batch_size = 128
num_classes = 10
epochs = 2
data_augmentation = False
num_predictions = 20
save_dir = os.path.join(os.getcwd(), 'saved_models/cifar10-1-crap')
model_name = 'model'
learning_rate = 0.1
decay_rate = learning_rate / epochs
momentum = 0.7


# Save model and weights
if not os.path.isdir(save_dir):
    os.makedirs(save_dir)

class BatchWeightsSaver(Callback):
    def __init__(self, model, N):
        self.model = model
        self.N = N
        self.batch = 0

    def on_batch_end(self, batch, logs={}):
        if self.batch % self.N == 0:
            name = 'weights-batch%08d.h5' % self.batch
            self.model.save_weights(save_dir+"/"+name)
        self.batch += 1

class EpochWeightsSaver(Callback):
    def __init__(self, model, N):
        self.model = model
        self.N = N
        self.epoch = 0

    def on_epoch_end(self, epoch, logs={}):
        if self.epoch % self.N == 0:
            name = 'weights-epoch-%08d.h5' % self.epoch
            self.model.save_weights(save_dir+"/"+name)
        self.epoch += 1


# The data, split between train and test sets:
(x_train, y_train), (x_test, y_test) = cifar10.load_data()
print('x_train shape:', x_train.shape)
print(x_train.shape[0], 'train samples')
print(x_test.shape[0], 'test samples')

# Convert class vectors to binary class matrices.
y_train = keras.utils.to_categorical(y_train, num_classes)
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

    return model;

model = get_model()

# initiate RMSprop optimizer
# opt = keras.optimizers.rmsprop(lr=0.0001, decay=1e-6)
opt = keras.optimizers.SGD(lr=learning_rate, momentum=momentum, decay=decay_rate, nesterov=False)

# Let's train the model using RMSprop
model.compile(loss='categorical_crossentropy',
            optimizer=opt,
            metrics=['accuracy'])
print(model.summary())

x_train = x_train.astype('float32')
x_test = x_test.astype('float32')
x_train /= 255
x_test /= 255

model.fit(x_train, y_train,
            batch_size=batch_size,
            epochs=epochs,
            validation_data=(x_test, y_test),
            # validation_split = 0.2,
            shuffle=True,
            callbacks=[EpochWeightsSaver(model, 1)])

model_path = os.path.join(save_dir, model_name)
# model.save(model_path)
model_json = model.to_json();
with open(model_path+".json", "w") as json_file:
    json_file.write(model_json)

model.save_weights(save_dir + '/' + 'final.h5')
# print('Saved trained model at %s ' % model_path)

# saving
the_weights = model.get_weights()
np.save(save_dir + "/weights_array", the_weights)

# Score trained model.
scores = model.evaluate(x_test, y_test, verbose=1)
print('Test loss:', scores[0])
print('Test accuracy:', scores[1])

# new_model = get_model()
new_json_file = open(model_path+'.json','r')
new_model_json = new_json_file.read()
new_json_file.close()
new_model = model_from_json(new_model_json)
new_model.load_weights(save_dir+'/'+'final.h5')
new_model.compile(loss='categorical_crossentropy',
                optimizer=opt,
                metrics=['accuracy'])
 
scores = new_model.evaluate(x_test, y_test, verbose=1)
print('Test loss:', scores[0])
print('Test accuracy:', scores[1])

# loading upon restarting the kernel
the_weights_2 = np.load(save_dir + '/weights_array.npy')
new_model.set_weights(the_weights_2)

scores = new_model.evaluate(x_test, y_test, verbose=1)
print('Test loss:', scores[0])
print('Test accuracy:', scores[1])

