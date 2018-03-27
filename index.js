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
	mrProcess = child_process.spawn('adb', ['shell', 'monkey', '-p', appPkg, '-v', '500', '--throttle', '50'], {stdio: 'inherit'});
	console.log('LOG Started monkey runner');
	return new Promise((res, rej) => {
		function l() {
			res();
			mrProcess.removeListener('exit', l);
			mrProcess.removeListener('error', m);
		}

		function m(err) {
			rej(err)
			mrProcess.removeListener('exit', l);
			mrProcess.removeListener('error', m);
		}
		mrProcess.on('exit', l);
		mrProcess.on('error', m);
	});
}

function executeDroidBot(apkDirPath, apkFile) {
	dbProcess = child_process.spawn('droidbot', ['-a', apkFile, '-o', path.join(apkDirPath, 'db_op')]);
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

async function runApk(apkDirPath, {fDevice, deviceId}) {
	const files = await readdir(apkDirPath);
	let apkPath = null, apiPath = null;	
	for(let file of files) {
		if(path.extname(file) === '.apk') {
			apkPath = path.join(apkDirPath, file);
		} else if(path.extname(file) === '.txt') {
			apiPath = path.join(apkDirPath, file);
		}
	}

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
					console.log('FAILURE-LOG Uninstall Failed');
					continue;
				}
				console.log('LOG Installing ' + deviceId);
				child_process.spawnSync(`adb`, ['install', '-rg', apkPath]);
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
				//console.log('LOG Granting permissions');
				//child_process.execSync(`adb shell pm grant ${appPkg} android.permission.WRITE_EXTERNAL_STORAGE`);
				//child_process.execSync(`adb shell pm grant ${appPkg} android.permission.READ_EXTERNAL_STORAGE`);
				//console.log('LOG Granted permissions');
			case 5:
				await executeMonkeyRunner(appPkg);
				console.log('LOG Monkeyed');
				progressCode++;
				//await executeDroidBot(apkDirPath, apkPath);
			case 6:
				try {
					console.log('LOG Uninstalling App');
					await client.uninstall(deviceId, appPkg);
					console.log('LOG Uninstalled');
				} catch(err) {continue;}
				progressCode++;
			}

			
		} catch(err) {console.log(err);}
	}
	console.log('LOG Done APK')
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
	/*const files = await readdir(datasetPath);
	for(let file of files) {
		const fileStat = fs.statSync(path.join(datasetPath, file));
		if(fileStat.isDirectory()) {
			try {
				await runApk(path.join(datasetPath, file), {fDevice, deviceId});
			} catch(err) {
				console.log('FATAL-ERROR ' + file + err);
			}
		}
	}*/
	await runApk(datasetPath, {fDevice, deviceId});
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
