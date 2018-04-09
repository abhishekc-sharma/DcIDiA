const adb = require('adbkit');
const client = adb.createClient();
const frida = require('frida');
const path = require('path');
const fs = require('fs');
const util = require('util');
const apkreader = require('adbkit-apkreader');
const child_process = require('child_process');
const datasetPath = process.argv[2];

const readFile = util.promisify(fs.readFile);
const readdir = util.promisify(fs.readdir);

const generateScript = require('./generateScript');

function sleep(ms) {
	return new Promise(function(res, rej) {
		setTimeout(function() {res()}, ms);
	});
}

async function executeMonkeyRunner(appPkg) {
	//child_process.execSync(`adb shell input keyevnt 4`);
	//await sleep(2000);
	//console.log('LOG sent back button');
	mrProcess = child_process.spawn('adb', ['shell', 'monkey', '-p', appPkg, '-v', '--throttle', '500', '500']);
	console.log('LOG Started monkey runner');
	return Promise.race([new Promise((res, rej) => {
				mrProcess.on('exit', () => res());
				mrProcess.on('error', () => res());			
			}),
			sleep(1000 * 60 * 3).then(() => {
				console.log('LOG Timing out Monkey')
				mrProcess.kill('SIGINT');
				res();
			})
		]);
}

function executeDroidBot(apkDirPath, apkFile) {
	dbProcess = child_process.spawn('droidbot', ['-a', apkFile, '-o', path.join(apkDirPath, 'db_op')], {stdio: 'inherit'});
	console.log('LOG started droidbot');
	return Promise.race([
		new Promise((res, rej) => {
			dbProcess.on('exit', () => res());
			dbProcess.on('error', (err) => rej(err));
		}),
		sleep(1000 * 60 * 30).then(() => {
			dbProcess.kill('SIGINT');
		})
	]);
}

async function runApk(apkDirPath, obj) {
	const files = await readdir(apkDirPath);
	let apkPath = null, apiPath = null;	
	for(let file of files) {
		if(path.extname(file) !== '.txt') {
			continue;
		} /*else if(path.extname(file) === '.txt') {
			apiPath = path.join(apkDirPath, file);
		}*/
		console.log(file, apkDirPath);
		const apiPath = path.join(apkDirPath, file);
		const apkPath = path.join(apkDirPath, file.slice(5,file.indexOf('.')) + '.apk');	
		try {
			await runNow(apkPath, apiPath, obj);
		} catch(err) {
			const fDevice = obj.fDevice;
			const deviceId = obj.deviceId;
			console.log('LOG Error');
		}
	}
}

async function runNow(apkPath, apiPath, {fDevice, deviceId}) {
	if(apkPath === null || apiPath === null) {
		throw new Error('Did not find apk or txt');
	}
	console.log('LOG Apk ' + apkPath + ' ' + apiPath);
	const reader = await apkreader.open(apkPath);
	const manifest = await reader.readManifest();
	const appPkg = manifest.package;
	console.log('LOG Package ' + appPkg);
	const maxRetries = 3;
	let retries = -1, progressCode = 0, pid, session, script;
	while(progressCode < 7 && retries < maxRetries) {
		retries++;
		try {
			switch(progressCode) {
			case 0:
				console.log('LOG Uninstalling');
				try {
				await client.uninstall(deviceId, appPkg);
				} catch(err) {
					console.log(err + 'FAILURE-LOG Uninstall Failed');
					continue;
				}
				console.log('LOG Installing ' + deviceId);
				await client.install(deviceId, apkPath);
				console.log('LOG Installed');
				await sleep(5000);	
				try {
					pid = await fDevice.spawn([appPkg]);
				} catch(err) {
					console.log('FAILURE-LOG Spawn failed');

					continue;
				}
				await sleep(1000);
				progressCode++;
			case 1:
				try {
					await fDevice.resume(pid);
					console.log('LOG PID ' + pid);
				} catch(err) {
					console.log('FAILURE-LOG Resume failed');
					continue;
				}
				await sleep(10000);
				progressCode++;
			case 2:
				try {
					session = await fDevice.attach(pid);
					console.log('LOG Session attached');
				} catch(err) {
					console.log('FAILURE-LOG Attach failed');
					continue;					
				}
				await sleep(1000);
				progressCode++;
			case 3:		
				const scriptTxt = await generateScript(apiPath);
				console.log('LOG Generated script');
				try {
					script = await session.createScript(scriptTxt);
					console.log('LOG Created script');
				} catch(err) {
					console.log('FAILURE-LOG Create Script Failed');
					continue;
				}

				progressCode++;
			case 4:
				try {
					await script.load();
				} catch(err) {
					console.log('LOG intial timeout');
					await waitDone(script);
					console.log('LOG Recovered from timeout');
				}
				await sleep(10000);
				progressCode++;
			case 5:
				await executeMonkeyRunner(appPkg);
				console.log('LOG Monkeyed');
				//await executeDroidBot(apkDirPath, apkPath);
				progressCode++;
			case 6:
				try {
					console.log('LOG Uninstalling App');
					await client.uninstall(deviceId, appPkg);
					console.log('LOG Uninstalled');
				} catch(err) {console.log(err); continue;}
				progressCode++;
			}

			
		} catch(err) {console.log(err);}
	}
	if(progressCode < 7) {
		console.log('LOG Uninstalling due to error');
		await client.uninstall(deviceId, appPkg);
	} else {
		console.log('LOG Done APK');
	}
}
function waitDone(script) {
	return new Promise((resolve, reject) => {
		console.log('LOG Waiting for done message')
		script.events.listen('message', message => {
			console.log('LOG Got Message')
			console.log(message)
			if(message.type === 'send' && message.payload && message.payload.done === 'Loaded') resolve();
		});
	});
}
async function run() {
	console.log('LOG Starting Run');
	const fDevice = await frida.getUsbDevice(); 
	const devices = await client.listDevices();
	const deviceId = devices[0].id;
	console.log('LOG Device ' + deviceId);
	const files = await readdir(datasetPath);
	for(let file of files) {
		const fileStat = fs.statSync(path.join(datasetPath, file));
		if(fileStat.isDirectory()) {
			try {
				await runFamily(path.join(datasetPath, file), {fDevice, deviceId});
			} catch(err) {
				console.log('FATAL-ERROR ' + file + err);
			}
		}
	}
	//await runApk(datasetPath, {fDevice, deviceId});
}

async function runFamily(familyDirPath, obj) {
	const files = await readdir(familyDirPath);
	for(let file of files) {
		const fileStat = fs.statSync(path.join(familyDirPath, file));
		if(fileStat.isDirectory()) {
			await runApk(path.join(familyDirPath, file), obj);
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
