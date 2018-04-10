const path = require('path');
const fs = require('fs');
const util = require('util');
const child_process = require('child_process');
const datasetPath = process.argv[2];

const readFile = util.promisify(fs.readFile);
const readdir = util.promisify(fs.readdir);

async function run() {
	console.log('LOG Starting Run');
	const files = await readdir(datasetPath);
	for(let file of files) {
		const fileStat = fs.statSync(path.join(datasetPath, file));
		if(fileStat.isDirectory()) {
			try {
				await runFamily(path.join(datasetPath, file));
			} catch(err) {
				console.log('FATAL-ERROR ' + file + err);
			}
		}
	}
}

async function runFamily(familyDirPath) {
	const files = await readdir(familyDirPath);
	for(let file of files) {
		const fileStat = fs.statSync(path.join(familyDirPath, file));
		if(fileStat.isDirectory()) {
			await runApk(path.join(familyDirPath, file));
			//console.log(file);
		}
	} 
}

async function runApk(apkDirPath, obj) {
	const files = await readdir(apkDirPath);	
	for(let file of files) {
		if(path.extname(file) !== '.txt') {
			continue;
		}
		const apiPath = path.join(apkDirPath, file);
		try {
			child_process.execSync(`node dynamicfromapk.js ${apiPath}`, {stdio: ['pipe', 'inherit', 'pipe']});
		} catch(err) {
			console.log('LOG Error');
		}
	}
}

if(!datasetPath) {
	console.log('Provide path to dataset');
} else {
	run().then(() => {
		console.log('LOG Done');
	}).catch(err => {
		console.log(err);
	});
}
