import os
from bs4 import BeautifulSoup
import requests
import wget


CURR_CATEGORY = CURR_FOLDER = 'food_and_drink'


if os.path.exists('./' + CURR_FOLDER):
	os.rmdir('./' + CURR_FOLDER)
os.mkdir(CURR_FOLDER)
os.chdir('./' + CURR_FOLDER)


url = 'https://apkpure.com/' + CURR_CATEGORY
r  = requests.get(url)
data = r.text

soup = BeautifulSoup(data, "html.parser")
main_div = soup.find("ul", {"class": "category-template"})

for list_item in main_div.find_all('li'):
	
	download_button = list_item.find("div", {"class": "category-template-down"})
	link = download_button.find('a')
	
	resource = link.get('href')
	resource = 'https://apkpure.com' + resource
	
	print(resource, end = ',   ')

	page = requests.get(resource)
	page_data = page.text
	page_soup = BeautifulSoup(page_data, "html.parser")
	page_main_a = page_soup.find("a", {"id": "download_link"})

	apk_link = page_main_a.get('href')
	apk = requests.get(apk_link, stream = True)

	with open(resource.split("/")[3]+'.apk', 'wb') as apk_file:
		for chunk in apk.iter_content(chunk_size=1024*1024):
			if chunk:
				apk_file.write(chunk)


	print('...... DONE')

