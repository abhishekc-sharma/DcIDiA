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

function executeMonkeyRunner(appPkg) {
	child_process.execSync(`adb shell monkey -p ${appPkg} -v 500`);
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
	try {
		await client.uninstall(deviceId, appPkg);
	} catch(err) {}
	await client.install(deviceId, apkPath);
	const pid = await fDevice.spawn([appPkg]);
	await fDevice.resume(pid);
	await sleep(1000);
	console.log('LOG PID ' + pid);
	const session = await fDevice.attach(pid);
	console.log('LOG Session attached');
	const scriptTxt = await generateScript(apiPath);
	//console.log(apkPath + scriptTxt);
	const script = await session.createScript(scriptTxt);
	console.log('LOG Created script');
	try {
		await script.load();
	} catch(err) {
		console.log('LOG intial timeout');
		await waitDone(script);
	}
	console.log('LOG Recovered from timeout');
	executeMonkeyRunner(appPkg);
	console.log('LOG Monkeyed')
	await client.uninstall(deviceId, appPkg);
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
