const util = require('util');
const fs = require('fs');
const LineByLineReader = require('line-by-line');

const getHookImplementationFn = function(className, methodName, argTypesStr) {
	return `function() {
		console.log('EVENT ${className} ${methodName}');
		const args = [].slice.call(arguments);
		try {
			const result = this.${methodName}.overload(${argTypesStr}).apply(this, args);
		} catch(err) {
			console.log('LOG ' + err);
		}		
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
	return `try {
		if(!${className.replace(/\./g, '_')}Instance) 
		var ${className.replace(/\./g, '_')}Instance = Java.use("${className}");
	} catch(err) {}`;
}

function methodHook(className, methodName, implementationFn) {
	return `try {
		${className.replace(/\./g, '_')}Instance.${methodName}.implementation = ${implementationFn};
	} catch(err) { }`;
}

function overloadedMethodHook(className, methodName, argTypes = [], count) {
	argTypesStr = argTypes.map(argType => `"${argType}"`).join(',');
	implementationFn = getHookImplementationFn(className, methodName, argTypesStr);
	return `try {
		${className.replace(/\./g, '_')}Instance.${methodName}.overload(${argTypesStr}).implementation = ${implementationFn};
		console.log('LOG Hooked ${count}');
	} catch(err) {
		console.log('LOG Hook ${count} failed');
	}
	`;
}


async function generateScript(inputLines) {
	return new Promise((resolve, reject) => {
		let op = `if(Java.available) {
				console.log('LOG Java is available');
				Java.perform(function() {
		`
		let hookCount = 0;
		for(let line of inputLines) {
			if(line.indexOf('<') == -1 || line.indexOf('$') != '-1') continue;
			const parts = line.split(/[<:\s()>,]/).filter(part => part.length > 0);
			const className = parts[0], methodName = parts[2];
			op += classInstance(className);
			op += overloadedMethodHook(className, methodName, parts.slice(3, parts.length - 1), hookCount); 
			hookCount = hookCount + 1;
		}

		op += `
			});
			console.log('LOG all hooks completed');
			send({done: 'Loaded'});
		}
		`;
	});
}

module.exports = generateScript;
