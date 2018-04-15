
import subprocess
import sys

# PERMISSIONS PART

ALLOWED_LIST = ['ACCESS_COARSE_LOCATION', 'ACCESS_FINE_LOCATION', 'ACCESS_NETWORK_STATE', 'ACCESS_WIFI_STATE', 'CAMERA', 'CHANGE_WIFI_STATE', 'GET_ACCOUNTS', 'GET_TASKS', 'INTERNET', 'READ_EXTERNAL_STORAGE', 'READ_PHONE_STATE', 'RECEIVE_BOOT_COMPLETED', 'RECORD_AUDIO', 'SET_WALLPAPER', 'SYSTEM_ALERT_WINDOW', 'VIBRATE', 'WAKE_LOCK', 'WRITE_EXTERNAL_STORAGE', 'WRITE_SETTINGS', 'android.c2dm.permission.RECEIVE', 'browser.permission.READ_HISTORY_BOOKMARKS', 'browser.permission.WRITE_HISTORY_BOOKMARKS', 'launcher.permission.INSTALL_SHORTCUT', 'launcher.permission.READ_SETTINGS', 'vending.BILLING']


output = subprocess.check_output(["aapt", "d", "permissions", sys.argv[1]])

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
