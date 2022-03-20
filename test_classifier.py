import tensorflow as tf
import numpy as np
from tensorflow.keras.preprocessing.image import ImageDataGenerator, load_img, img_to_array
from tensorflow.keras.models import Model
from tensorflow.keras.models import load_model
from tensorflow.keras.layers import Input, Flatten, Dense, Dropout, GlobalAveragePooling2D
from tensorflow.keras.applications.mobilenet import MobileNet, preprocess_input
import math

TRAIN_DATA_DIR = ''
VALIDATION_DATA_DIR = ''
TRAIN_SAMPLES = 500
VALIDATION_SAMPLES = 500
NUM_CLASSES = 2
IMG_WIDTH, IMG_HEIGHT = 224, 224

model = load_model('model.h5')

img_path = '/home/willk/Pictures/nn_test_404.jpg'
img_path2 = '/home/willk/Pictures/nn_test_active.jpg'

img = load_img(img_path, target_size=(224,224))
img2 = load_img(img_path2, target_size=(224,224))

img_array = img_to_array(img)
img_array2 = img_to_array(img2)

expanded_img_array = np.expand_dims(img_array, axis=0)
expanded_img_array2 = np.expand_dims(img_array2, axis=0)

preprocessed_img = preprocess_input(expanded_img_array) # Preprocess
preprocessed_img2 = preprocess_input(expanded_img_array2) # Preprocess the image

prediction = model.predict(preprocessed_img)
prediction2 = model.predict(preprocessed_img2)

print(prediction)
print(prediction2)
