const LineByLineReader = require('line-by-line');

if(process.argv.length < 3) {
	process.stderr.write('Enter path to output file\n');
	process.exit(1);
}

const fileName = process.argv[2];
console.log(fileName);
const lr = new LineByLineReader(fileName);
let status = false;
const apiCountMap = new Map();
const currentApi = new Set();
let count = 0;
let lc = 1;
lr.on('line', line => {
	if(line.startsWith('LOG Session') && status === false) {
		status = true;
	} else if(line.startsWith('LOG Done') && status === true) {
		currentApi.clear();
		status = false;
		count++;
	} else if(line.startsWith('EVENT') && status === true) {
		const classMethod = line.split(' ').slice(1).join('.');
		if(!currentApi.has(classMethod)) {
			currentApi.add(classMethod);
			if(!apiCountMap.has(classMethod)) {
				apiCountMap.set(classMethod, 0);
			}

			apiCountMap.set(classMethod, apiCountMap.get(classMethod) + 1);
		}
	} else if(status === false && line.startsWith('EVENT')) {
		process.stderr.write('Unexpected ordering ' + lc + '\n');
	} 
	lc++
});

lr.on('end', () => {
	process.stdout.write(`${count} APKs processed`);
	console.log(apiCountMap);
});
