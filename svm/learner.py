from sklearn import preprocessing
import csv
import numpy as np
import random
from sklearn.svm import SVC, LinearSVC
ratio = 0.7
ds = open('fv.csv')
rdr = csv.reader(ds)
data = list(rdr)
data = np.array(random.sample(data,len(data)))
labels = np.array(data[:,(len(data[0])-1)])
labels = labels.astype(np.int)
fvs = np.array(data[:,:(len(data[0])-1)])
fvs = fvs.astype(np.int)
split = int(ratio*len(data))
traindata = fvs[:split]
trainlabel = labels[:split]
testdata = fvs[split:]
testlabel = labels[split:]
mod = SVC()
mod.fit(traindata,trainlabel)
print((mod.score(testdata,testlabel)*100))
