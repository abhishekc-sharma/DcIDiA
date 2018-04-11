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

#try:
#	sys.argv[2]
#except IndexError:
#	print("Please provide destination path")
#	sys.exit(1)
inp_list = open("apkpaths.txt","w")
#dest_dir = sys.argv[2]
for fam in os.listdir(source_dir):
	#os.makedirs(dest_dir+fam+"/")
	flag = 0
	for var in os.listdir(source_dir+fam+"/"):
		#os.makedirs(dest_dir+fam+"/"+var+"/")
		if(os.path.isdir(os.path.join(source_dir,fam,var))):
			if(len(os.listdir(source_dir+fam+"/"+var+"/")) < 20):
				filenames = random.sample(os.listdir(source_dir+fam+"/"+var+"/" ), len(os.listdir(source_dir+fam+"/"+var+"/")))
			else:
				filenames = random.sample(os.listdir(source_dir+fam+"/"+var+"/" ), 20)
			for j in filenames:
				print(fam+"/"+var+"/"+j,file=inp_list)
		else: 
			flag = 1
	if flag == 1:
		if(len(os.listdir(source_dir+fam+"/")) < 20):
			filenames = random.sample(os.listdir(source_dir+fam+"/"), len(os.listdir(source_dir+fam+"/")))
		else:
			filenames = random.sample(os.listdir(source_dir+fam+"/" ), 20)
		for j in filenames:
			print(fam+"/"+j,file=inp_list)