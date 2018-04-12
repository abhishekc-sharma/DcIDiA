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
	print("Please provide path to apk")
	sys.exit(1)

apkpath , apk = os.path.split(sys.argv[1])

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


args = [os.path.join("./", maraPath, "mara.sh"),"-s",sys.argv[1]]
subprocess.call(args, cwd=maraPath)
if os.path.exists(os.path.join(maraPath, "data", apk, "smali/apktool/")):
	apkSmaliPath = os.path.join(maraPath, "data", apk, "smali/apktool/")
elif os.path.exists(os.path.join(maraPath, "data", apk, "smali/baksmali/")):
	apkSmaliPath = os.path.join(maraPath, "data", apk, "smali/baksmali/")
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
#final = open("testfinal"+apk+".txt","w")
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
							#final.write(finwrite)
							lineset.add(finwrite)
os.remove(apk+".txt")
#final.close()
danger = ["READ_CALENDAR","WRITE_CALENDAR","CAMERA","READ_CONTACTS","WRITE_CONTACTS","GET_ACCOUNTS","ACCESS_FINE_LOCATION","ACCESS_COARSE_LOCATION","RECORD_AUDIO","READ_PHONE_STATE", "READ_PHONE_NUMBERS","CALL_PHONE","ANSWER_PHONE_CALLS","READ_CALL_LOG", "WRITE_CALL_LOG","ADD_VOICEMAIL","USE_SIP","PROCESS_OUTGOING_CALLS","ANSWER_PHONE_CALLS", "BODY_SENSORS","SEND_SMS","RECEIVE_SMS","READ_SMS","RECEIVE_WAP_PUSH","RECEIVE_MMS","READ_EXTERNAL_STORAGE","WRITE_EXTERNAL_STORAGE"]
permis = {}
with open("jellybean_publishedapimapping","r") as jpam:
	for line in jpam:
		title,val = line.split(":")
		if title == "Permission":
			permis[val.strip("\n")] = []
			lsp = val.strip("\n")
		if re.search('^(\<)',title):
			#print("Last seen permission for"+ title+" is "+ lsp)
			pak = title.split("<")[1]
			method = val.split(" ")[2].split("(")[0]
			permis[lsp].append(pak+" "+method)
shortlistset = set()
#print(lineset)
for x in lineset:
	pkg1,met1= x.split(">")[0].split(":")
	#print(pkg1,met1)
	pkg = pkg1.split("<")[1]
	met = met1.split(" ")[2].split("(")[0]
	#print(pkg,met)
	cmpstr = pkg+" "+met
	for key,value in permis.items():
		if cmpstr in value:
			p = key.split(".")[2]
			#print(p)
			if p in danger:
				shortlistset.add(x.strip("\n"))
API_ALLOWED_LIST=['<android.location.LocationManager: RETURN_TYPE getLastKnownLocation(java.lang.String,android.permission.ACCESS_FINE_LOCATION,android.permission.ACCESS_COARSE_LOCATION)> (CATEGORY)', '<android.telephony.TelephonyManager: RETURN_TYPE getDeviceId()> (CATEGORY)', '<android.telephony.TelephonyManager: RETURN_TYPE getLine1Number(android.permission.READ_PHONE_STATE)> (CATEGORY)', '<android.telephony.TelephonyManager: RETURN_TYPE getSubscriberId()> (CATEGORY)', '<android.location.LocationManager: RETURN_TYPE isProviderEnabled(java.lang.String,android.permission.ACCESS_FINE_LOCATION,android.permission.ACCESS_COARSE_LOCATION)> (CATEGORY)', '<android.telephony.SmsManager: RETURN_TYPE sendTextMessage(java.lang.String,java.lang.String,java.lang.String,android.app.PendingIntent,android.app.PendingIntent)> (CATEGORY)', '<android.telephony.TelephonyManager: RETURN_TYPE getCellLocation(android.permission.ACCESS_FINE_LOCATION,android.permission.ACCESS_COARSE_LOCATION)> (CATEGORY)', '<android.location.LocationManager: RETURN_TYPE getBestProvider(android.location.Criteria,boolean,android.permission.ACCESS_FINE_LOCATION,android.permission.ACCESS_COARSE_LOCATION)> (CATEGORY)', '<android.telephony.TelephonyManager: RETURN_TYPE getSimSerialNumber()> (CATEGORY)', '<android.telephony.SmsManager: RETURN_TYPE sendMultipartTextMessage(java.lang.String,java.lang.String,java.util.ArrayList,java.util.ArrayList,java.util.ArrayList)> (CATEGORY)', '<android.location.LocationManager: RETURN_TYPE getProviders(boolean)> (CATEGORY)', '<android.location.LocationManager: RETURN_TYPE getProviders(android.location.Criteria,boolean)> (CATEGORY)', '<android.telephony.TelephonyManager: RETURN_TYPE getNeighboringCellInfo()> (CATEGORY)', '<android.telephony.gsm.SmsManager: RETURN_TYPE sendTextMessage(java.lang.String,java.lang.String,java.lang.String,android.app.PendingIntent,android.app.PendingIntent)> (CATEGORY)', '<android.accounts.AccountManager: RETURN_TYPE getAccounts()> (CATEGORY)', '<android.location.LocationManager: RETURN_TYPE addGpsStatusListener(android.location.GpsStatus$Listener)> (CATEGORY)', '<android.location.LocationManager: RETURN_TYPE getProvider(java.lang.String)> (CATEGORY)', '<android.accounts.AccountManager: RETURN_TYPE getAccountsByType(java.lang.String)> (CATEGORY)', '<android.telephony.TelephonyManager: RETURN_TYPE getDeviceSoftwareVersion()> (CATEGORY)', '<android.telephony.gsm.SmsManager: RETURN_TYPE sendMultipartTextMessage(java.lang.String,java.lang.String,java.util.ArrayList,java.util.ArrayList,java.util.ArrayList,android.permission.SEND_SMS)> (CATEGORY)', '<android.accounts.AccountManager: RETURN_TYPE getAuthToken(android.accounts.Account,java.lang.String,android.os.Bundle,boolean,android.accounts.AccountManagerCallback,android.os.Handler)> (CATEGORY)', '<android.accounts.AccountManager: RETURN_TYPE getAuthToken(android.accounts.Account,java.lang.String,boolean,android.accounts.AccountManagerCallback,android.os.Handler,android.permission.USE_CREDENTIALS,android.permission.MANAGE_ACCOUNTS,android.permission.GET_ACCOUNTS)> (CATEGORY)', '<android.accounts.AccountManager: RETURN_TYPE getAuthToken(android.accounts.Account,java.lang.String,android.os.Bundle,android.app.Activity,android.accounts.AccountManagerCallback,android.os.Handler,android.permission.USE_CREDENTIALS,android.permission.MANAGE_ACCOUNTS,android.permission.GET_ACCOUNTS)> (CATEGORY)', '<android.accounts.AccountManager: RETURN_TYPE addAccount(java.lang.String,java.lang.String,java.lang.String[],android.os.Bundle,android.app.Activity,android.accounts.AccountManagerCallback,android.os.Handler)> (CATEGORY)', '<android.location.LocationManager: RETURN_TYPE sendExtraCommand(java.lang.String,java.lang.String,android.os.Bundle)> (CATEGORY)']
API_ALLOWED_LIST.sort()
fv = [0]*(len(API_ALLOWED_LIST))
for x in shortlistset:
	j = 0
	#print("\n")
	for j in range(len(API_ALLOWED_LIST)):
		if API_ALLOWED_LIST[j] == x.strip("\n"):
			#print(x,API_ALLOWED_LIST[j])
			fv[j] = 1
with open("trial.txt","w") as tr:
	print(str(fv).translate(None,'[]'),file=tr)