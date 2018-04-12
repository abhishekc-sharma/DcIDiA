const bytes = require('bytes');
const fs = require('fs');
const got = require('got');
const ora = require('ora');
const path = require('path');
const puppeteer = require('puppeteer');

let appCount = 0;
const ROOT_URL = `https://apkpure.com`;
(async () => {
	if(process.argv.length != 5) {
		console.log('Usage: node index.js <destination folder> <start category(1-32)> <end category(1-32)>');
		process.exit(0);
	}

	const downloadBase = process.argv[2];
	const startCategory = process.argv[3], endCategory = process.argv[4];
	if(startCategory > endCategory) {
		throw new Error('Start cannnot be higher than end');
	}
	const browser = await puppeteer.launch({headless: true});
	
	const page = await browser.newPage();
	const MAIN_URL = 'https://apkpure.com/app';
	
	await page.goto(MAIN_URL);
	
	const allCategoryList = await page.$$eval('ul.index-category', divs => {
		const div = divs[1];
		return Array.from(div.querySelectorAll('li a')).map(link => link.getAttribute('href'));
	});

	//console.log(categoryList);
	categoryList = allCategoryList.slice(startCategory - 1, endCategory - 1);
	
	for(const categoryUrl of categoryList) {
		const catPage = await browser.newPage();
		try {
			await startCategoryDownload(browser, catPage, `${ROOT_URL}${categoryUrl}`, downloadBase);
		} catch(err) {
			console.log('ERROR CATEGORY' + err);
		}		
		await catPage.close();
	}
	//await page.waitFor(10000);
	//console.log(categoryList);
	await browser.close();
})().catch(err => {
	console.log('FATAL ERROR ' + err);
});

async function startCategoryDownload(browser, page, url, baseDir) {
	
	for(let i = 1; i <= 3; i++) {
		await page.goto(`${url}?page=${i}`);
		const appUrls = await page.$$eval('ul#pagedata li div.category-template-img a', links => links.map(link => link.getAttribute('href')));		
		for(const appUrl of appUrls) {
			const appPage = await browser.newPage();
			try {
				await downloadApk(appPage, `${ROOT_URL}${appUrl}/download?from=category`, baseDir);
			} catch(err) {
				console.log('ERROR APK ' + err)
			}
			await appPage.close();
		}
	}
	
}

async function downloadApk(page, url, baseDir) {
	try {
		await page.goto(url, {timeout: 1, waitUntil: 'domcontentloaded'});
	} catch(err) {}
	await page.waitForSelector('h1 span.file');
	await page.waitForSelector('a#download_link');
	const appName = await page.$eval('h1 span.file', el => el.innerText.replace(' ', '').split(' ')[0]);
	const appUrl = await page.$eval('a#download_link', a => a.href);
	try {
		await downloadToFile(appUrl, path.join(baseDir, `${appName}.apk`));
	} catch(err) {
		console.log('ERROR DOWNLOAD' + err);
	}
}

function downloadToFile(url, fileName) {
	return new Promise((resolve, reject) => {
		const stream = got.stream(url);
		appCount++;
		const spinner = ora(`App ${appCount} - 0%`);
		spinner.start();
		stream.on('downloadProgress', (progress) =>  {
			spinner.text = `App ${appCount} - ${(progress.percent * 100).toFixed(2)}% of ${bytes(progress.total)}`;
		});
		const finalStream = stream.pipe(fs.createWriteStream(fileName));
		stream.on('end', () => {
			spinner.succeed();
			resolve();
		});
		stream.on('error', (err) => {
			spinner.fail();
			reject(err)
		});
	});
}
