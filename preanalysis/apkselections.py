from __future__ import print_function
import os, sys
import shutil
import random
from shutil import copyfile
try:
	sys.argv[1]
except IndexError:
	print("Please provide source path to dataset")
	sys.exit(1)
source_dir = sys.argv[1]
yy = len(source_dir)
inp_list = open("apkpaths.txt","w")
for root,dirs,files in os.walk(source_dir):
	if len(files) == 0:
		continue
	elif len(files) < 20:
		for name in files:
			print(os.path.join(root[yy:],name),file=inp_list)
	else:
		filenams = random.sample(files,20)
		for name in filenams:
			print(os.path.join(root[yy:],name),file=inp_list)
