import numpy as np
import keras
import os
from keras.models import model_from_json

permissions = np.array(os.environ['PERMISSIONS'].split(','), dtype=int)
apis = np.array(os.environ['APIS'].split(','), dtype=int)
dynamic = np.array(os.environ['DYNAMIC'].split(','), dtype=int)
static = np.concatenate([permissions, apis]);
hybrid = np.concatenate([permissions, dynamic])

permissions = np.reshape(permissions, (1, permissions.shape[0]))
apis = np.reshape(apis, (1, apis.shape[0]))
dynamic = np.reshape(dynamic, (1, dynamic.shape[0]))
static = np.reshape(static, (1, static.shape[0]))
hybrid = np.reshape(hybrid, (1, hybrid.shape[0]))

json_file = open('permissions_model.json', 'r')
loaded_model_json = json_file.read()
json_file.close()
permissions_model = model_from_json(loaded_model_json)
permissions_model.load_weights("permissions_model.h5")
permissions_model.compile(optimizer='nadam', loss='binary_crossentropy', metrics=['accuracy'])

json_file = open('apis_model.json', 'r')
loaded_model_json = json_file.read()
json_file.close()
apis_model = model_from_json(loaded_model_json)
apis_model.load_weights("apis_model.h5")
apis_model.compile(optimizer='nadam', loss='binary_crossentropy', metrics=['accuracy'])

json_file = open('dyn_model.json', 'r')
loaded_model_json = json_file.read()
json_file.close()
dyn_model = model_from_json(loaded_model_json)
dyn_model.load_weights("dyn_model.h5")
dyn_model.compile(optimizer='nadam', loss='binary_crossentropy', metrics=['accuracy'])

json_file = open('static_model.json', 'r')
loaded_model_json = json_file.read()
json_file.close()
static_model = model_from_json(loaded_model_json)
static_model.load_weights("static_model.h5")
static_model.compile(optimizer='nadam', loss='binary_crossentropy', metrics=['accuracy'])

json_file = open('hybrid_model.json', 'r')
loaded_model_json = json_file.read()
json_file.close()
hybrid_model = model_from_json(loaded_model_json)
hybrid_model.load_weights("hybrid_model.h5")
hybrid_model.compile(optimizer='nadam', loss='binary_crossentropy', metrics=['accuracy'])

'''
sample = np.array(features, dtype=int)
sample = np.reshape(sample, (1, sample.shape[0]))

prediction = permissions_model.predict(sample)
print(prediction[0][0])
'''

permissions_prediction = permissions_model.predict(permissions)[0][0]
apis_prediction = apis_model.predict(apis)[0][0]
dyn_prediction = dyn_model.predict(dynamic)[0][0]
static_prediction = static_model.predict(static)[0][0]
hybrid_prediction = hybrid_model.predict(hybrid)[0][0]

print('Permissions, Static APIs, Dynamic APIs, Static, Hybrid :', permissions_prediction, apis_prediction, dyn_prediction, static_prediction, hybrid_prediction)
