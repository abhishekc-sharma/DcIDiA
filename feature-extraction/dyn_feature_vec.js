const apis = [
	'android.net.ConnectivityManager.getActiveNetworkInfo',
	'android.telephony.TelephonyManager.getDeviceId',
	'android.net.NetworkInfo.getType',
	'android.app.PendingIntent.getBroadcast',
	'android.app.admin.DevicePolicyManager.isAdminActive',
	'android.telephony.TelephonyManager.getNetworkOperatorName',
	'android.net.ConnectivityManager.getNetworkInfo',
	'android.os.Environment.getExternalStorageDirectory',
	'android.os.Environment.getExternalStorageState',
	'android.database.sqlite.SQLiteOpenHelper.getWritableDatabase',
	'android.os.Parcel.setDataPosition',
	'android.os.Handler.sendMessageDelayed',
	'android.view.View.getAnimation',
	'android.app.Activity.getSystemService',
	'android.content.ContextWrapper.getBaseContext',
	'android.view.View.getBackground',
	'android.view.View.getVisibility',
	'android.view.View.setVisibility',
	'android.content.res.Resources.getDisplayMetrics',
	'android.view.View.getLayoutDirection',
	'android.content.Intent.setExtrasClassLoader',
	'android.accounts.AccountManager.getAccounts',
	'android.app.ActivityManager.getRunningTasks',
	'android.app.ActivityManager.getRunningAppProcesses',
	'android.webkit.WebView.getSettings',
	'android.telephony.TelephonyManager.getSubscriberId',
	'android.preference.PreferenceManager.getDefaultSharedPreferences'
]

const fs = require('fs');
const path = require('path');
const util = require('util');
const childProcess = require('child_process');

fs.readdir = util.promisify(fs.readdir);
fs.stat = util.promisify(fs.stat);
fs.readFile = util.promisify(fs.readFile);

let apkDirectory;
let counter = 0;
let success = 0;
let failed = 0;
async function main() {
	const dataDirectory = process.argv[2];
	apkDirectory = process.argv[3];
	const results = await processDir(dataDirectory);
	const resultStr = results.join('\n');
	console.log(resultStr);
	process.stderr.write(`${counter} ${success} ${failed}`);
}

async function processDir(dirPath) {
	const dirContents = await fs.readdir(dirPath);
	let combinedResults = [];
	for(let dirItem of dirContents) {
		dirItem = path.join(dirPath, dirItem);
		dirItemStat = await fs.stat(dirItem);
		if(dirItemStat.isFile() && dirItem.includes('dynOp')) {
			let result;
			try {
				result = await processFile(dirItem);
				if(!result) continue;
			} catch(err) {
				process.stderr.write('Some error\n');			
			}
			combinedResults.push(result);
		} else if(dirItemStat.isDirectory()) {
			const results = await processDir(dirItem);
			combinedResults = combinedResults.concat(results);
		}
	}
	return combinedResults;
}

async function processFile(filePath) {
	counter++;
	const contents = await fs.readFile(filePath, {encoding: 'utf-8'});
	const contentLines = contents.split('\n').filter(line => line.includes('EVENT')  && !line.includes('android.widget'));
	if(contentLines.length < 30) {
		failed++;		
		return false;
	}
	const apiSet = new Set();
	for(const line of contentLines) {
		const classMethod = line.split(' ').slice(1).join('.');
		if(apis.includes(classMethod) && !apiSet.has(classMethod)) {
			apiSet.add(classMethod);
		}
		if(apiSet.size === apis.length) {
			break;
		}	
	}

	const featureVec = [];
	let count = 0;
	for(const api of apis) {
		if(apiSet.has(api)) {
			featureVec.push(1);
			count++;
		} else {
			featureVec.push(0);
		}
	}

	let apkPermissions;	
	try {
	const apkPath = path.basename(filePath.replace('dynOp', ''));
	const actualApkPath = childProcess.execSync(`find "${apkDirectory}" -name "${apkPath}"`, { encoding: 'utf-8' }).trim().split('\n')[0];
	apkPermissions = childProcess.execSync(`python3 apk_permissions.py "${actualApkPath}"`, { encoding: 'utf-8' }).trim();

	} catch(err) {
		process.stderr.write('beebop\n');
		return false;
	}
	success++;
	return apkPermissions + featureVec.join(',');
}

main().catch(err => {
	console.log(err);
	console.log('Usage: node dyn_feature_vec.js <path_to_data_dir>');
});
