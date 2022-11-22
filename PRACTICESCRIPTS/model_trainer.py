#!/usr/bin/env python3

# This code has been adapted from examples on Chapter 3 of "Practical Deep Learning"
#   by Anirudh Koul, Siddha Ganju, and Meher Kasam.

import tensorflow as tf
from tensorflow.keras.preprocessing.image import ImageDataGenerator
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Flatten, Dense, Dropout, GlobalAveragePooling2D
from tensorflow.keras.applications.mobilenet import MobileNet, preprocess_input
import math

TRAIN_DATA_DIR = 'TRAINING_DATA/TRAIN'
VALIDATION_DATA_DIR = 'TRAINING_DATA/VALIDATION'
TRAIN_SAMPLES = 1317
VALIDATION_SAMPLES = 140
NUM_CLASSES = 2
IMG_WIDTH, IMG_HEIGHT = 224, 224
BATCH_SIZE = 64


def model_maker():
    """Model Maker

    removes task-specific fully connected layers of the ResNet-50 model and
    builds a new custom model to be trained
    """
    base_model = MobileNet(include_top=False, input_shape=(IMG_WIDTH,IMG_HEIGHT,3))
    for layer in base_model.layers[:]:
        layer.trainable = False # Freeze the layers
        input = Input(shape=(IMG_WIDTH, IMG_HEIGHT, 3))
        custom_model = base_model(input)
        custom_model = GlobalAveragePooling2D()(custom_model)
        custom_model = Dense(64, activation='relu')(custom_model)
        custom_model = Dropout(0.5)(custom_model)
        predictions = Dense(NUM_CLASSES, activation='softmax')(custom_model)
    return Model(inputs=input, outputs=predictions)


# training data generation, supplements data provided by me
# also performs various preprocessing transformation on the new data
#   to achieve invariance
train_datagen = ImageDataGenerator(preprocessing_function=preprocess_input,
                                    rotation_range=20,
                                    width_shift_range=0.2,
                                    height_shift_range=0.2,
                                    zoom_range=0.2)

# validation data
val_datagen = ImageDataGenerator(preprocessing_function=preprocess_input)

# generate data
train_generator = train_datagen.flow_from_directory(TRAIN_DATA_DIR,
                                                    target_size=(IMG_WIDTH, IMG_HEIGHT),
                                                    batch_size=BATCH_SIZE,
                                                    shuffle=True,
                                                    seed=12345,
                                                    class_mode='categorical')
validation_generator = val_datagen.flow_from_directory(VALIDATION_DATA_DIR,
                                                        target_size=(IMG_WIDTH, IMG_HEIGHT),
                                                        batch_size=BATCH_SIZE,
                                                        shuffle=False,
                                                        class_mode='categorical')

# example of the classes used to categorize the data
# uses name of folder they are in by default
print(validation_generator.class_indices)

# define model
model = model_maker()
model.compile(loss='categorical_crossentropy',
              optimizer= tf.optimizers.Adam(lr=0.001),
              metrics=['acc'])

# iterations
num_steps = math.ceil(float(TRAIN_SAMPLES)/BATCH_SIZE)

# train/validate the model
model.fit_generator(train_generator,
                    steps_per_epoch = num_steps,
                    epochs=10,
                    validation_data = validation_generator,
                    validation_steps = num_steps)

model.save('model2.h5')
