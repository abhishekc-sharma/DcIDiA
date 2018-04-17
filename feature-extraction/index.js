const androidctrl = require('./androidctrl');
const commander = require('commander');
const commandExists = require('command-exists');
const fs = require('fs');
const LineByLineReader = require('line-by-line');
const path = require('path');
const util = require('util');
const childProcess = require('child_process');

const APK_PERMISSIONS_SCRIPT = '';
const APK_APIS_SCRIPT = '';
const APK_DYN_APIS_SCRIPT = '';

fs.access = util.promisify(fs.access);
fs.readdir = util.promisify(fs.readdir);
fs.readFile = util.promisify(fs.readFile);
fs.stat = util.promisify(fs.stat);
fs.writeFile = util.promisify(fs.writeFile);

const globalProgress = {
	total: 0,
	current: 0,
	error: 0
};

let fridapath, emulatorName;
async function ensurePrerequisites() {
	try {
		await Promise.all([
			commandExists('adb'),
			commandExists('wc'),
			commandExists('find'),
			commandExists('python'),
			commandExists('python3'),
			commandExists('aapt'),
			commandExists('emulator')
		]);
	} catch(err) {
		throw new Error('adb not found in PATH');
	}
}

async function checkAndParseEnv() {
	if(!process.env['MARA_PATH']) {
		throw new Error('Environment variable MARA_PATH not found');
	}

	if(!process.env['MARA_PATH']) {
		throw new Error('Environment variable EMULATOR_PATH not found');
	}
}

async function checkAndEnsureArgs(commander) {
	if(!commander.data) {
		throw new Error('Missing required option --data|-d');
	}

	if(!commander.data && commander.file) {
		throw new Error('Specified --file|-f without --data|-d');
	}

	
	if(commander.data) {
		try {
			if(!path.isAbsolute(commander.data)) {
				throw new Error(`Argument to --data|-d has to be an absolute path`);
			}
			await fs.access(commander.data, fs.constants.R_OK | fs.constants.X_OK);
		} catch(err) {
			throw new Error(`Argument to --data|-d '${commander.data}' either is not an absolute path, does not exist or not correct permissions`)

		}	
	} 
	
	if(commander.file) {
		try {
			await fs.access(commander.file, fs.constants.R_OK);
		} catch(err) {
			throw new Error(`Argument to --file|-f '${commander.file}' either is not an absolute path, does not exist or is not readable`);	
		}
	}

	if(!commander.output) {
		throw new Error(`Missing required argument --output|-o`);
	}

	if(!commander.avd) {
		throw Error('Missing option --avd');
	}
	
	/*let res = await androidctrl.hasAVD(`${commander.avd}`);
	if(!res) {
		throw Error(`Argument to --avd ${commander.avd} does not exist`);
	}*/

	if(!commander.frida) {
		throw Error('Missing option --frida');
	}
	fridaPath = commander.frida;
	emulatorName = commander.avd;

	commander.index = commander.index || 1;
	commander.index = parseInt(commander.index, 10);
}

async function main() {
	await ensurePrerequisites();
	await checkAndParseEnv();
	commander
		.version('1.0.0')
		.option('-f, --file <datapathsfile>', 'OPTIONAL | Process APKs from file with one path to and APK per line')
		.option('-i, --index <apkindex>', 'DEFAULT: 1 | Index starting from 1 to start processing APKs from when -f|--file is used', )
		.option('-d, --data <datapath>', 'REQUIRED | Process APKs recursively starting from directory')
		.option('-o, --output <outputpath>', 'REQUIRED | Path to the file to write output')
		.option('-t, --type <apkstype>', 'DEFAULT: malware | Indicate if input APKs are goodware or malware [malware|goodware]', /^(malware|goodware)$/, 'malware')
		.option('--avd <AVDName>', 'REQUIRED | Name of the avd to use')
		.option('--frida <FirdaServerPath>', 'REQUIRED | Path to frida-server executable to use')
		.parse(process.argv);
	await checkAndEnsureArgs(commander);
	const apkType = commander.type === 'malware' ? 1 : 0;
	const opStream = fs.createWriteStream(commander.output);
	if(commander.file) {
		await processDataFile(commander.file, commander.data, commander.index, opStream);
	} else if(commander.data) {
		await processDataDir(commander.data, { first: true }, opStream);
	}
	opStream.end();
}

async function processDataDir(dataPath, { first }, opStream) {
	if(first) {
		const apkCount = parseInt(childProcess.execSync(`find ${dataPath} -name "*.apk" | wc -l`, {encoding: 'utf-8'}).trim(), 10);
		globalProgress.total = apkCount;
		console.log(`(${globalProgress.current}, ${globalProgress.error})/${globalProgress.total}`);
	}
	
	const directoryContents = await fs.readdir(dataPath);
	for(let directoryItem of directoryContents) {
		directoryItem = path.join(dataPath, directoryItem);
		directoryItemStat = await fs.stat(directoryItem);
		if(directoryItemStat.isFile() && path.extname(directoryItem) === '.apk') {
			const apkStatus = await processApk(directoryItem, opStream);
			if(apkStatus) {
				globalProgress.current += 1;
			} else {
				globalProgress.error += 1;
			}
			console.log(`(${globalProgress.current}, ${globalProgress.error})/${globalProgress.total}`);
		} else if(directoryItemStat.isDirectory()) {
			await processDataDir(directoryItem, { first: false}, opStream);
		}
	}
}

async function processDataFile(filePath, dataPath, index, opStream) {
	const apkCount = parseInt(childProcess.execSync(`wc -l ${filePath}`, { encoding: 'utf-8' }).split(' ')[0], 10);
	globalProgress.total = apkCount;
	globalProgress.current = index - 1;
	console.log(`(${globalProgress.current}, ${globalProgress.error})/${globalProgress.total}`);
	let i = 0;
	const apkLines = await fs.readFile(filePath, { encoding: 'utf-8'}).then((res) => res.split('\n').filter(l => l.length > 0));
	for(let apkPath of apkLines) {
		i++;
		if(i < index) {
			continue;
		}
		await checkAndSetupEmulator();
		apkPath = path.join(dataPath, `"${apkPath}"`);
		console.log(apkPath);
		const apkStatus = await processApk(apkPath, opStream);
		if(apkStatus) {
			globalProgress.current += 1;
		} else {
			globalProgress.error += 1;
		}
		console.log(`(${globalProgress.current}, ${globalProgress.error})/${globalProgress.total}`);
	}
	console.log('OMG Done');
}

async function processApk(apkPath, opStream) {
	let apkPermissions;
	try {
		apkPermissions = childProcess.execSync(`python3 apk_permissions.py ${apkPath}`, { encoding: 'utf-8' }).trim();
	} catch(err) {
		console.log('Error Permissions');
		return false;
	}
	console.log('Permissions');
	let apkApisOp; 
	try {
		apkApisOp = childProcess.execSync(`python3 apk_apis.py ${apkPath} ../dont_look_inside/Ouput_CatSinks_v0_9.txt ../dont_look_inside/Ouput_CatSources_v0_9.txt`, { encoding: 'utf-8'}).split('\n');
	} catch(err) {
		console.log('Error Static APIs');
		return false;
	}
	const apkApis = apkApisOp[0].trim();
	if(apkApis.startsWith('Error')) {
		return false;
	}
	console.log('Static APIs');
	opStream.write(apkPermissions + apkApis + '\n');
	apkApisOp = apkApisOp.slice(1, apkApisOp.length - 1);
	await fs.writeFile('./apisFile', JSON.stringify(apkApisOp));
	const dynOpFile = path.join(path.dirname(apkPath), path.basename(apkPath) + 'dynOp');
	try {
		childProcess.execSync(`node apk_dyn_apis.js ./apisFile ${apkPath} > ${dynOpFile}`);
	} catch(err) {
		console.log('Error Dynamic APIs');
		return true;
	}
	console.log('Dynamic APIs');
	return true;
}

async function checkAndSetupEmulator() {
	let res = await androidctrl.devices(emulatorName);
	if(!res.length) {
		console.log('Starting AVD');
		const {id} = await androidctrl.start(emulatorName);
		await androidctrl.ensureReady(id);
		await androidctrl.adb(id, `push ${fridaPath} /data/local/tmp/frida-server`);
		await androidctrl.adb(id, `shell chmod 755 /data/local/tmp/frida-server`);
		childProcess.exec(`adb shell /data/local/tmp/frida-server`);
		console.log('Started');
	}
}

main().catch(err => console.log('FATAL-ERROR ' + err));
