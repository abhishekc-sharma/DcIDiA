from __future__ import print_function
import re
import os
import subprocess
for ds_root, ds_dir, ds_file in os.walk("/home/andro/Desktop/dataset/"):
	for apk in ds_file:
		args = ["./mara.sh","-s",os.path.join(ds_root,apk)]
		subprocess.call(args)

apknames =  os.listdir("/home/andro/Desktop/Tools/MARA_Framework/data/")
for apkname in apknames:
	#print "apk :" + apkname
	crt = open(apkname+".txt","w")
	for iroot, idirs, ifiles in os.walk("/home/andro/Desktop/Tools/MARA_Framework/data/" + apkname+"/smali/apktool/"):
			#f = open("/home/andro/Desktop/Tools/MARA_Framework/data/airpush1.apk/smali/apktool/com/airpush/android/h.smali","r")
		for name in ifiles:
			f = open(os.path.join(iroot,name),"r")
			#print "file :" + name
			f1 = f.readlines()
			for x in f1:
  				if re.search('invoke-.*(Landroid|Ljava).*',x):
					print((str(re.findall('\w+',x.split('}')[1].split('-')[0])).translate(None, '[],\'')).replace(" ",".")[1:], end = " ", file = crt)
					print(':', end = " ", file = crt)
					print(re.findall('\w+',x.split('}')[1].split('-')[1])[0],file = crt)
	subprocess.call(["sort",apkname+".txt", "-o" ,"sorted"+apkname+".txt"])

