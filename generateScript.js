const util = require('util');
const fs = require('fs');
const LineByLineReader = require('line-by-line');

const inFileName = process.argv[2];
const outFileName = process.argv[3];
console.log(inFileName, outFileName);
const lr = new LineByLineReader(inFileName);
const op = fs.createWriteStream(outFileName);
const seenClasses = new Set();

op.write(
`if(Java.available) {
	console.log('Java is available');
Java.perform(function() {
	const activeSources = new Map();`);

const getHookImplementationFn = function(className, methodName, argTypesStr) {
	return `function() {
		const args = [].slice.call(arguments);
		const result = this.${methodName}.overload(${argTypesStr}).apply(this, args);
		return result;
	}`;
}

const getSourceHookImplementationFn = function(className, methodName, argTypesStr) {
	return `function() {
		const args = [].slice.call(arguments);
		const result = this.${methodName}.overload(${argTypesStr}).apply(this, args);
		activeSources.set(result.hashCode(), {sourceFunction: className + '.' + methodName + '(' + argTypesStr + ')'});
		return result;
	}`;
}

const getSinkHookImplementationFn = function(className, methodName, argTypesStr) {
	return `function() {
		const args = [].slice.call(arguments);
		const sourcedArgs = args.filter(function(arg) {
			activeSources.has(arg.hashCode());
		});

		sourcedArgs.forEach(function(arg) {
			const obj = activeSources.get(arg.hashCode());
			obj.sinkFunction = className + '.' + methodName + '(' + argTypesStr + ')';
			activeSources.set(arg.hashCode(), obj);
		});
		const result = this.${methodName}.overload(${argTypesStr}).apply(this, args);
		return result;
	}`;
}

function classInstance(className) {
	return `
		var ${className.replace(/\./g, '_')}Instance = Java.use("${className}");
	`;
}

function methodHook(className, methodName, implementationFn) {
	return `
		${className.replace(/\./g, '_')}Instance.${methodName}.implementation = ${implementationFn};
	`;
}

function overloadedMethodHook(className, methodName, argTypes = []) {
	argTypesStr = argTypes.map(argType => `"${argType}"`).join(',');
	implementationFn = getHookImplementationFn(className, methodName, argTypesStr);
	return `
		${className.replace(/\./g, '_')}Instance.${methodName}.overload(${argTypesStr}).implementation = ${implementationFn};
	`;
}


lr.on('line', line => {
	if(line.indexOf('<') == -1 || line.indexOf('$') != '-1') return;
	const parts = line.split(/[<:\s()>,]/).filter(part => part.length > 0);
	const className = parts[0], methodName = parts[2];
	if(!seenClasses.has(className)) {
		op.write(classInstance(className));
		seenClasses.add(className);
	}

	op.write(overloadedMethodHook(className, methodName, parts.slice(3, parts.length - 1))); 
});

lr.on('end', () => {
	op.write(`
		});
	}
	`);
	op.end();
});

lr.on('error', (err) => {
	console.log(err);
});

