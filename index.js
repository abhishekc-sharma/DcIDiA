const adb = require('adbkit');
const client = adb.createClient();
const frida = require('frida');
const path = require('path');
const fs = require('fs');
const util = require('util');
const apkreader = require('adbkit-apkreader');
const apkPath = process.argv[2];

const readFile = util.promisify(fs.readFile);

function sleep(ms) {
	return new Promise(function(res, rej) {
		setTimeout(function() {res()}, ms);
	});
}

async function run() {
	const apkProp = path.parse(apkPath);
	if(apkProp.ext != '.apk') {
		throw new Error('Not valid apk file');
	}
	console.log('Opening the APK');
	const reader = await apkreader.open(apkPath);
	console.log('Done');
	console.log('Reading Manifest File');
	const manifest = await reader.readManifest();
	console.log('Done');
	const appPkg = manifest.package;
	if(!appPkg) {
		throw new Error('Unable to get app package name');
	}
	const fDevice = await frida.getUsbDevice();
	const devices = await client.listDevices();
	console.log(devices);
	const deviceId = devices[0].id;
	console.log('Installing APK on device');
	await client.install(deviceId, apkPath);
	console.log('Done');
	const pid = await fDevice.spawn([appPkg]);
	await fDevice.resume(pid);
	await sleep(1000); 
	console.log(pid);
	const session = await fDevice.attach(pid);
	const scriptTxt = await readFile('s.js', 'utf-8');
	const script = await session.createScript(scriptTxt);
	script.events.listen('message', message => {
		console.log(message);	
	});
	await script.load();
	setInterval(function() {}, 60 * 60 * 1000);
}

if(!apkPath) {
	console.log('Provide path to apk');
} else {
	run().then(() => {
		console.log('Done');
	}).catch(err => {
		console.log(err);
	});
}
