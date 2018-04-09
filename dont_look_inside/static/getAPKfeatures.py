import subprocess
import sys


IS_MALWARE = sys.argv[2]

# PERMISSIONS PART

ALLOWED_LIST = ['INTERNET', 'READ_PHONE_STATE', 'ACCESS_NETWORK_STATE', 'ACCESS_COARSE_LOCATION', 'RECEIVE_BOOT_COMPLETED', \
			'ACCESS_FINE_LOCATION', 'ACCESS_WIFI_STATE', 'WRITE_EXTERNAL_STORAGE','launcher.permission.INSTALL_SHORTCUT','GET_ACCOUNTS', \
			'browser.permission.READ_HISTORY_BOOKMARKS','VIBRATE','WAKE_LOCK','launcher.permission.READ_SETTINGS', \
			'browser.permission.WRITE_HISTORY_BOOKMARKS','GET_TASKS','SET_WALLPAPER','WRITE_SETTINGS','READ_EXTERNAL_STORAGE', \
			'vending.BILLING', 'android.c2dm.permission.RECEIVE', 'CAMERA', 'SYSTEM_ALERT_WINDOW', 'RECORD_AUDIO', 'CHANGE_WIFI_STATE']
ALLOWED_LIST.sort()

output = subprocess.check_output(["aapt", "d", "permissions", sys.argv[1]])

# print (output)

features = output.decode().strip("\n").split("\n")[1:]

i = 0
for f in features:
	features[i] = f.split('.')[2:][0][0:-1]
	i = i + 1

features.sort()
j = 0
k = 0
for j in range(len(ALLOWED_LIST)):
	while(k < len(features) and features[k] < ALLOWED_LIST[j]):
		k = k + 1
	
	if k < len(features) and features[k] == ALLOWED_LIST[j]:
		print ("1", end=",")
		k = k + 1
	else:
		print ("0", end=",")
	
	


# API CALLS PART




print(IS_MALWARE)

