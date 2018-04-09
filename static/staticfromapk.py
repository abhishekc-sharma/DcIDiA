
with open("mal_perms.txt", "r") as gf:
	content = gf.readlines()

gp = open("mal.csv", "w")

allowed_list = ['INTERNET', 'READ_PHONE_STATE', 'ACCESS_NETWORK_STATE', 'ACCESS_COARSE_LOCATION', 'RECEIVE_BOOT_COMPLETED', \
			'ACCESS_FINE_LOCATION', 'ACCESS_WIFI_STATE', 'WRITE_EXTERNAL_STORAGE','launcher.permission.INSTALL_SHORTCUT','GET_ACCOUNTS', \
			'browser.permission.READ_HISTORY_BOOKMARKS','VIBRATE','WAKE_LOCK','launcher.permission.READ_SETTINGS', \
			'browser.permission.WRITE_HISTORY_BOOKMARKS','GET_TASKS','SET_WALLPAPER','WRITE_SETTINGS','READ_EXTERNAL_STORAGE', \
			'vending.BILLING', 'android.c2dm.permission.RECEIVE', 'CAMERA', 'SYSTEM_ALERT_WINDOW', 'RECORD_AUDIO', 'CHANGE_WIFI_STATE']
allowed_list.sort()

i = 0
temp = []

while(i < len(content)):
	content[i] = content[i].strip("\n")

	if content[i] == "\n":
		i = i + 1
		continue

	if content[i] == '!!!':
		temp.sort()

		#print(allowed_list)
		#print(temp)

		j = 0
		k = 0
		for j in range(len(allowed_list)):
			#gp.write(",")
			if len(temp)-k > 0 and temp[k].strip() == allowed_list[j]:
				gp.write("1,")
				print("1", end=",")
				k = k + 1
			else:
				gp.write("0,")
				print("0", end=",")
		gp.write("1")
		temp = []
		i = i + 1
		
		if i >= len(content):
			break

		while content[i] == "\n":
			i = i + 1
		gp.write("\n")
		#gp.write(content[i].strip("\n"))
		
		#print(content[i])
		
		i = i + 1
	
	if content[i] in allowed_list:
		temp.append(content[i])
	i = i + 1;

gp.close()
