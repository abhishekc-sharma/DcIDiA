'use strict';

var ezspawn = require('ezspawn');
var fs = require('fs');
var path = require('path');
var spawnWaitFor = require('spawn-wait-for');
var returnUndefined = function() {
  return undefined;
};

var processKeyValueGroups = function(str) {
  var lines = str.split('\n');
  var currentKey = {};
  var results = [];

  lines.forEach(function(line) {
    var matches = line.match(/([\w\/]+):\s(.*)/);
    var key;
    var value;

    if (matches === null) {
      return;
    }

    key = matches[1];
    value = matches[2];

    if (typeof currentKey[key] !== 'undefined') {
      results.push(currentKey);
      currentKey = {};
    }

    currentKey[key] = value;
  });

  if (Object.keys(currentKey).length) {
    results.push(currentKey);
  }

  return results;
};

function sleep(ms) {
	return new Promise((resolve, reject) => {
		setTimeout(() => { resolve(); }, ms);
	});
}

var Android = {
  start: function(avdName) {
    return spawnWaitFor(
      'emulator -verbose -wipe-data -avd "' + avdName + '"',
      /emulator: control console listening on port (\d+), ADB on port \d+/
    ).then(function(result) {
      return {
        process: result.process,
        id: 'emulator-' + result.matches[1]
      };
    });
  },

  waitForDevice: function(emulatorId) {
    return this.adb(emulatorId, 'wait-for-device').then(returnUndefined);
  },

  ensureReady: async function(emulatorId) {
    var _this = this;
	await this.waitForDevice(emulatorId);
	for(let i = 0; i < 600; i++) {
		let proc;
		try {
		
		proc = await this.adb(emulatorId, 'shell getprop sys.boot_completed');
		} catch(err) {
			console.log('adb error');
			console.log(err);
		}
		if (!proc.stdout.match(/1/)) {
			await sleep(1000);
			continue;
		}

		return true;
	}

  },

  

  adb: function(emulatorId, cmd) {
    return ezspawn('adb -s ' + emulatorId + ' ' + cmd);
  },


  hasAVD: function(avdName) {
    return this.listAVDs().then(function(avds) {
		console.log(avds);
      return avds.filter(function(avd) {
        return avd.Name.toLowerCase() === avdName.toLowerCase();
      }).length > 0;
    });
  },


  stop: function(emulatorId) {
    return this.adb(emulatorId, 'emu kill');
  },


  devices: function() {
    return ezspawn('adb devices').then(function(output) {
      var lines = output.stdout.split('\n');
      lines.shift();
      return lines
        .map(function(line) {
          var matches = line.match(/([^\s]+)\s+([^\s]+)/);
          if (matches === null) {
            return null;
          }

          return {
            name: matches[1],
            status: matches[2]
          };
        })
        .filter(function(x) {
          return x !== null;
        });
    });
  },

  listAVDs: function() {
    return ezspawn('emulator -list-avds').then(function(output) {
      var avds = processKeyValueGroups(output.stdout);
		console.log(avds);
      return avds;
    });
  },
};

module.exports = Android;

