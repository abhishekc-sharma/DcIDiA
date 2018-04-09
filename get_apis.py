from __future__ import print_function
from sets import Set
import re
import sys
import os
import subprocess
import shutil

try:  
   os.environ["MARA_PATH"]
except KeyError: 
   print("Please set the environment variable MARA_PATH")
   sys.exit(1)

maraPath = os.environ["MARA_PATH"]

try:
	sys.argv[1]
except IndexError:
	print("Please provide path to apkpaths.txt")
	sys.exit(1)

datasetPath = sys.argv[1]

try:
	sys.argv[2]
except IndexError:
	print("Need at least one file to get Sources/Sinks from")
	sys.exit(1)

sosiClassDict = {}
for i in range(2, len(sys.argv)):
    input_file = sys.argv[i]
    with open(input_file) as f:
        for line in f:
            parts = re.compile("[<:\s(),>]").split(line)
            parts = [part for part in parts if len(part) > 0]
            if len(parts) <= 1:
                continue
            className = parts[0]
            methodName = parts[2]
            argsString = ",".join(parts[3:-1])
            if not (className in sosiClassDict):
                sosiClassDict[className] = (Set([]), {})
            sosiClassDict[className][0].add(methodName)
            if not (methodName in sosiClassDict[className][1]):
                sosiClassDict[className][1][methodName] = []
            sosiClassDict[className][1][methodName].append(argsString)

if os.path.exists(os.path.join(maraPath, "data")) and os.path.isdir(os.path.join(maraPath, "data")):
	shutil.rmtree(os.path.join(maraPath, "data"))
linenumber = 0;
with open(datasetPath,"r") as apkpaths:
	for pathe in apkpaths:
		linenumber  = linenumber + 1
		print("Line number:"+ str(linenumber))
		apk = os.path.split(pathe)[1].strip("\n")
		args = [os.path.join("./", maraPath, "mara.sh"),"-s",pathe]
		subprocess.call(args, cwd=maraPath)
		apkSmaliPath = os.path.join(maraPath, "data", apk, "smali/apktool/")
		crt = open(apk+".txt","w")
		for iroot, idirs, ifiles in os.walk(apkSmaliPath):
			for name in ifiles:
				with open(os.path.join(iroot,name),"r") as f:
					for x in f:
						if re.search('invoke-.*(Landroid).*',x):
							print((str(re.findall('\w+',x.split('}')[1].split('-')[0])).translate(None, '[],\'')).replace(" ",".")[1:], end = " ", file = crt)
							print(':', end = " ", file = crt)
							print(re.findall('\w+',x.split('}')[1].split('-')[1])[0],file = crt)
		#subprocess.call(["sort",apkname+".txt", "-o" ,"sorted"+apkname+".txt"])
		#shutil.rmtree(os.path.join(maraPath, "data", apk))
		crt.close()
		final = open(os.path.join(os.path.split(pathe)[0] ,"final"+apk+".txt"),"w")
		lineset = set()
		with open(apk+".txt", "r") as cur1:
			for x in cur1:
				if(len(x.split(":")) > 1):
					cname = str(re.findall("\w+",x.split(":")[0])).translate(None,'[],\'').replace(" ",".")
					mname = str(re.findall("\w+",x.split(":")[1])).translate(None,'[],\'')
					if(cname in sosiClassDict):
						if mname in sosiClassDict[cname][0]:
                                                    finwrite = ""
                                                    for argsString in sosiClassDict[cname][1][mname]:
							finwrite = "<" + cname + ": RETURN_TYPE " + mname + "(" + argsString + ")> (CATEGORY)\n"
						        if finwrite not in lineset:
							    final.write(finwrite)
							    lineset.add(finwrite)
		os.remove(apk+".txt")
		final.close()
		curapkdatapath = "data/"+apk
		if os.path.exists(os.path.join(maraPath, curapkdatapath)) and os.path.isdir(os.path.join(maraPath, curapkdatapath)):
			shutil.rmtree(os.path.join(maraPath, curapkdatapath))
	
				
