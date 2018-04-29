import numpy as np
from sklearn.model_selection import train_test_split
import csv
import keras
import tensorflow as tf
from keras import backend as K
from keras.models import Sequential
from keras import optimizers
from keras.layers import Dense, Dropout

ds_goodware_apis = np.array(list(csv.reader(open('../data/goodware_apis.csv'))), dtype=int)
ds_malware_apis = np.array(list(csv.reader(open('../data/malware_apis.csv'))), dtype=int)

ds_goodware_permissions = np.array(list(csv.reader(open('../data/goodware_permissions_reduced.csv'))), dtype=int)
ds_malware_permissions = np.array(list(csv.reader(open('../data/malware_permissions_reduced.csv'))), dtype=int)

ds_goodware_dyn = np.array(list(csv.reader(open('../data/goodware_dyn.csv'))), dtype=int)
ds_malware_dyn = np.array(list(csv.reader(open('../data/malware_dyn.csv'))), dtype=int)

ds_goodware_static = np.array(list(csv.reader(open('../data/goodware_static.csv'))), dtype=int)
ds_malware_static = np.array(list(csv.reader(open('../data/malware_static.csv'))), dtype=int)

ds_goodware_hybrid = np.array(list(csv.reader(open('../data/goodware_hybrid.csv'))), dtype=int)
ds_malware_hybrid = np.array(list(csv.reader(open('../data/malware_hybrid.csv'))), dtype=int)



print('Goodware Static APIs :', ds_goodware_apis.shape)
print('Malware Static APIs :', ds_malware_apis.shape)
print('Goodware Permissions :', ds_goodware_permissions.shape)
print('Malware Permissions APIs :', ds_malware_permissions.shape)
print('Goodware Dynamic APIs :', ds_goodware_dyn.shape)
print('Malware Dynamic APIs :', ds_malware_dyn.shape)
print('Goodware Static :', ds_goodware_static.shape)
print('Malware Static :', ds_malware_static.shape)
print('Goodware Hybrid :', ds_goodware_hybrid.shape)
print('Malware Hybrid :', ds_malware_hybrid.shape)

ds_apis = np.concatenate([ds_goodware_apis, ds_malware_apis], axis = 0)
ds_permissions = np.concatenate([ds_goodware_permissions, ds_malware_permissions], axis = 0)
ds_dyn = np.concatenate([ds_goodware_dyn, ds_malware_dyn], axis = 0)
ds_static = np.concatenate([ds_goodware_static, ds_malware_static], axis = 0)
ds_hybrid = np.concatenate([ds_goodware_hybrid, ds_malware_hybrid], axis = 0)

print('\n')

print('Static APIs :', ds_apis.shape)
print('Permissions :', ds_permissions.shape)
print('Dynamic APIs :', ds_dyn.shape)
print('Static :', ds_static.shape)
print('Hybrid :', ds_hybrid.shape)

ds_apis_X = ds_apis[:, 0:ds_apis.shape[1] - 1]
ds_apis_Y = ds_apis[:, ds_apis.shape[1] - 1]

ds_permissions_X = ds_permissions[:, 0:ds_permissions.shape[1] - 1]
ds_permissions_Y = ds_permissions[:, ds_permissions.shape[1] - 1]

ds_dyn_X = ds_dyn[:, 0:ds_dyn.shape[1] - 1]
ds_dyn_Y = ds_dyn[:, ds_dyn.shape[1] - 1]

ds_static_X = ds_static[:, 0:ds_static.shape[1] - 1]
ds_static_Y = ds_static[:, ds_static.shape[1] - 1]

ds_hybrid_X = ds_hybrid[:, 0:ds_hybrid.shape[1] - 1]
ds_hybrid_Y = ds_hybrid[:, ds_hybrid.shape[1] - 1]

ds_apis_X_train, ds_apis_X_test, ds_apis_Y_train, ds_apis_Y_test = train_test_split(ds_apis_X, ds_apis_Y, test_size=0.33, random_state=42, shuffle=True)
ds_permissions_X_train, ds_permissions_X_test, ds_permissions_Y_train, ds_permissions_Y_test = train_test_split(ds_permissions_X, ds_permissions_Y, test_size=0.33, random_state=42, shuffle=True)
ds_dyn_X_train, ds_dyn_X_test, ds_dyn_Y_train, ds_dyn_Y_test = train_test_split(ds_dyn_X, ds_dyn_Y, test_size=0.33, random_state=42, shuffle=True)
ds_static_X_train, ds_static_X_test, ds_static_Y_train, ds_static_Y_test = train_test_split(ds_static_X, ds_static_Y, test_size=0.33, random_state=42, shuffle=True)
ds_hybrid_X_train, ds_hybrid_X_test, ds_hybrid_Y_train, ds_hybrid_Y_test = train_test_split(ds_hybrid_X, ds_hybrid_Y, test_size=0.33, random_state=42, shuffle=True)


print('\n')
print('Static APIs Train, Test ', ds_apis_X_train.shape, ds_apis_X_test.shape, ds_apis_Y_train.shape, ds_apis_Y_test.shape)
print('Permissions Train, Test ', ds_permissions_X_train.shape, ds_permissions_X_test.shape, ds_permissions_Y_train.shape, ds_permissions_Y_test.shape)
print('Dynamic APIs Train, Test ', ds_dyn_X_train.shape, ds_dyn_X_test.shape, ds_dyn_Y_train.shape, ds_dyn_Y_test.shape)
print('Static Train, Test ', ds_static_X_train.shape, ds_static_X_test.shape, ds_static_Y_train.shape, ds_static_Y_test.shape)
print('Hybrid Train, Test ', ds_hybrid_X_train.shape, ds_hybrid_X_test.shape, ds_hybrid_Y_train.shape, ds_hybrid_Y_test.shape)

def precision(y_true, y_pred):
    """Precision metric.

    Only computes a batch-wise average of precision.

    Computes the precision, a metric for multi-label classification of
    how many selected items are relevant.
    """
    true_positives = K.sum(K.round(K.clip(y_true * y_pred, 0, 1)))
    predicted_positives = K.sum(K.round(K.clip(y_pred, 0, 1)))
    precision = true_positives / (predicted_positives + K.epsilon())
    return precision

def recall(y_true, y_pred):
    """Recall metric.

    Only computes a batch-wise average of recall.

    Computes the recall, a metric for multi-label classification of
    how many relevant items are selected.
    """
    true_positives = K.sum(K.round(K.clip(y_true * y_pred, 0, 1)))
    possible_positives = K.sum(K.round(K.clip(y_true, 0, 1)))
    recall = true_positives / (possible_positives + K.epsilon())
    return recall

def f1(y_true, y_pred):
    def recall(y_true, y_pred):
        """Recall metric.

        Only computes a batch-wise average of recall.

        Computes the recall, a metric for multi-label classification of
        how many relevant items are selected.
        """
        true_positives = K.sum(K.round(K.clip(y_true * y_pred, 0, 1)))
        possible_positives = K.sum(K.round(K.clip(y_true, 0, 1)))
        recall = true_positives / (possible_positives + K.epsilon())
        return recall

    def precision(y_true, y_pred):
        """Precision metric.

        Only computes a batch-wise average of precision.

        Computes the precision, a metric for multi-label classification of
        how many selected items are relevant.
        """
        true_positives = K.sum(K.round(K.clip(y_true * y_pred, 0, 1)))
        predicted_positives = K.sum(K.round(K.clip(y_pred, 0, 1)))
        precision = true_positives / (predicted_positives + K.epsilon())
        return precision
    precision = precision(y_true, y_pred)
    recall = recall(y_true, y_pred)
    return 2*((precision*recall)/(precision+recall))

permissions_model = Sequential()
permissions_model.add(Dense(units=50, activation='relu', input_dim=ds_permissions_X.shape[1]))
permissions_model.add(Dropout(0.4))
permissions_model.add(Dense(units=20, activation='relu'))
permissions_model.add(Dense(units=1, activation='sigmoid'))
permissions_model.compile(optimizer='nadam', loss='binary_crossentropy', metrics=['accuracy', precision, recall, f1])
permissions_model.fit(ds_permissions_X_train, ds_permissions_Y_train, epochs=40, batch_size=128)

permissions_model_score = permissions_model.evaluate(ds_permissions_X_test, ds_permissions_Y_test, batch_size=32)
print(permissions_model_score)

permissions_model_json = permissions_model.to_json()
with open("permissions_model.json", "w") as json_file:
    json_file.write(permissions_model_json)
permissions_model.save_weights("permissions_model.h5")



apis_model = Sequential()
apis_model.add(Dense(units=35, activation='relu', input_dim=ds_apis_X.shape[1]))
apis_model.add(Dropout(0.25))
apis_model.add(Dense(units=1, activation='sigmoid'))
apis_model_optimizer = optimizers.Nadam(0.005)
apis_model.compile(optimizer=apis_model_optimizer, loss='binary_crossentropy', metrics=['accuracy', precision, recall, f1])
apis_model.fit(ds_apis_X_train, ds_apis_Y_train, epochs=50, batch_size=128)

apis_model_score = apis_model.evaluate(ds_apis_X_test, ds_apis_Y_test, batch_size=128)
print(apis_model_score)

apis_model_json = apis_model.to_json()
with open("apis_model.json", "w") as json_file:
    json_file.write(apis_model_json)
apis_model.save_weights("apis_model.h5")

dyn_model = Sequential()
dyn_model.add(Dense(units=40, activation='relu', input_dim=ds_dyn_X.shape[1]))
dyn_model.add(Dropout(0.75))
dyn_model.add(Dense(units=1, activation='sigmoid'))
dyn_model_optimizer = optimizers.Nadam(lr=0.008)
dyn_model.compile(optimizer=dyn_model_optimizer, loss='binary_crossentropy', metrics=['accuracy', precision, recall, f1])
dyn_model.fit(ds_dyn_X_train, ds_dyn_Y_train, epochs=50, batch_size=32)

dyn_model_score = dyn_model.evaluate(ds_dyn_X_test, ds_dyn_Y_test, batch_size=128)
print(dyn_model_score)


dyn_model_json = dyn_model.to_json()
with open("dyn_model.json", "w") as json_file:
    json_file.write(dyn_model_json)
dyn_model.save_weights("dyn_model.h5")

static_model = Sequential()
static_model.add(Dense(units=50, activation='relu', input_dim=ds_static_X.shape[1]))
static_model.add(Dropout(0.6))
static_model.add(Dense(units=10, activation='relu'))
static_model.add(Dense(units=1, activation='sigmoid'))
static_model_optimizer = optimizers.Nadam(lr=0.005)
static_model.compile(optimizer=static_model_optimizer, loss='binary_crossentropy', metrics=['accuracy', precision, recall, f1])
static_model.fit(ds_static_X_train, ds_static_Y_train, epochs=50, batch_size=128)

static_model_score = static_model.evaluate(ds_static_X_test, ds_static_Y_test, batch_size=128)
print(static_model_score)

static_model_json = static_model.to_json()
with open("static_model.json", "w") as json_file:
    json_file.write(static_model_json)
static_model.save_weights("static_model.h5")

hybrid_model = Sequential()
hybrid_model.add(Dense(units=30, activation='relu', input_dim=ds_hybrid_X.shape[1]))
hybrid_model.add(Dropout(0.5))
hybrid_model.add(Dense(units=1, activation='sigmoid'))
hybrid_model_optimizer = optimizers.Nadam(lr=0.01)
hybrid_model.compile(optimizer=hybrid_model_optimizer, loss='binary_crossentropy', metrics=['accuracy', precision, recall, f1])
hybrid_model.fit(ds_hybrid_X_train, ds_hybrid_Y_train, epochs=50, batch_size=128)

hybrid_model_score = hybrid_model.evaluate(ds_hybrid_X_test, ds_hybrid_Y_test, batch_size=128)
print(hybrid_model_score)


hybrid_model_json = hybrid_model.to_json()
with open("hybrid_model.json", "w") as json_file:
    json_file.write(hybrid_model_json)
hybrid_model.save_weights("hybrid_model.h5")
