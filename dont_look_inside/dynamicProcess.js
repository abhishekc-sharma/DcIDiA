const LineByLineReader = require('line-by-line');

if(process.argv.length < 3) {
	process.stderr.write('Enter path to output file\n');
	process.exit(1);
}

const fileName = process.argv[2];
console.log(fileName);
const lr = new LineByLineReader(fileName);
const apiCountMap = new Map();
const currentApi = new Set();
let count = 0;
let lc = 1;
lr.on('line', line => {
	if(line.startsWith('LOG New APK')) {
		currentApi.clear();
		count++;
	} else if(line.startsWith('EVENT')) {
		const classMethod = line.split(' ').slice(1).join('.');
		if(!currentApi.has(classMethod)) {
			currentApi.add(classMethod);
			if(!apiCountMap.has(classMethod)) {
				apiCountMap.set(classMethod, 0);
			}

			apiCountMap.set(classMethod, apiCountMap.get(classMethod) + 1);
		}
	} 
	lc++
});

lr.on('end', () => {
	process.stdout.write(`${count} APKs processed`);
	const sortedMap = new Map(Array
		.from(apiCountMap)
		.sort((a, b) => {
			return b[1] - a[1];
		}).slice(0, 25)
	);
	console.log(sortedMap);
});
