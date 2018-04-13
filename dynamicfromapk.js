const adb = require('adbkit');
const apkreader = require('adbkit-apkreader');
const child_process = require('child_process');
const frida = require('frida');
const fs = require('fs');
const path = require('path');
const util = require('util');

const readFile = util.promisify(fs.readFile);
const readdir = util.promisify(fs.readdir);

const generateScript = require('./generateScript');

function sleep(ms) {
	return new Promise((resolve, reject) => {
		setTimeout(() => { resolve(); }, ms);
	});
}

async function executeMonkeyRunner(appPkg) {
	const mr = child_process.exec(`adb shell monkey -p ${appPkg} -v --throttle 500 500`, { timeout: 1000 * 60 * 1.5, killSignal: 'SIGKILL'});
	await new Promise((resolve, reject) => {
		mr.on('exit', () =>  { 
			resolve();
		});
		mr.on('error', () => { 
			resolve()
		});
	});
}

function waitDone(script) {
	return new Promise((resolve, reject) => {
		console.log('LOG Waiting for Done')
		script.events.listen('message', message => {
			console.log('LOG Got Message');
			if(message.type === 'send' && message.payload && message.payload.done === 'Loaded') resolve();
		});
	});
}

async function main() {
	try {
		const apiPath = process.argv[2];
		const apkPath = process.argv[3];
	} catch(err) {
		console.log('LOG Usage: node <thisscript.js> <path_to_txt> <path_to_apk>');
	}
	console.log('LOG New APK ', apiPath, apkPath);
	const fDevice = await frida.getUsbDevice();
	const client = adb.createClient();
	const devices = await client.listDevices();
	const deviceId = devices[0].id;
	console.log('LOG Device ' + deviceId);
	const reader = await apkreader.open(apkPath);
	const manifest = await reader.readManifest();
	const appPkg = manifest.package;
	console.log('LOG Package ' + appPkg);
	const MAX_RETRIES = 3;
	let retries = -1;
	while(retries < MAX_RETRIES - 1) {
		retries++;
		try {
			let pid, session, script;
			console.log('LOG Pre-Uninstall');
			try {
				await client.uninstall(deviceId, appPkg);
			} catch(err) {
				console.log('ERROR Pre-Uninstall');
				continue;
			}

			console.log('LOG Install');
			try {
				await client.install(deviceId, apkPath);
			} catch(err) {
				console.log('ERROR Install ' + err);
				continue;
			}

			await sleep(5000);
			console.log('LOG Spawn');
			try {
				pid = await fDevice.spawn([appPkg]);
			} catch(err) {
				console.log('ERROR Spawn ' + err);
				continue;
			}

			await sleep(1000);
			console.log('LOG Resume');
			try {
				await fDevice.resume(pid);
			} catch(err) {
				console.log('ERROR Resume');
				continue;
			}

			await sleep(10000);
			console.log('LOG Attach');
			try {
				session = await fDevice.attach(pid);	
			} catch(err) {
				console.log('ERROR Attach');
				continue;
			}

			await sleep(1000);
			console.log('LOG Generate');
			const scriptTxt = await generateScript(apiPath);

			console.log('LOG Create Script');
			try {
				script = await session.createScript(scriptTxt);
			} catch(err) {
				console.log('ERROR Create Script');
				continue;
			}

			try {
				await script.load();
			} catch(err) {
				console.log('LOG Load Timeout');
				await waitDone(script);
				console.log('LOG Recovered Timeout');
			}

			await sleep(5000);
			console.log('LOG Monkeyrunner');

			await executeMonkeyRunner(appPkg);
			console.log('LOG Monkeyed');

			console.log('LOG Post-Uninstall');
			try {
				await client.uninstall(deviceId, appPkg);
			} catch(err) {
				console.log('ERROR Post-Uninstall');
				continue;
			}

			break;
		} catch(err) {
			console.log('FATAL-ERROR ' + err);		
		}
	}
}

main().catch((err) => console.log('FATAL-ERROR ' + err));
