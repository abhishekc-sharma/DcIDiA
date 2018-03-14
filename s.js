if(Java.available) {
	console.log('Java is available');
Java.perform(function() {
		var android_location_LocationProviderInstance = Java.use("android.location.LocationProvider");
	
		android_location_LocationProviderInstance.getName.overload().implementation = function() {
		const args = [].slice.call(arguments);
		console.log('getName called with: ');
		console.log(args[0]);
		const result = this.getName.overload().apply(this, args);
		console.log('Result: ' + result);
		return result;
	};
	
		var android_telephony_CellLocationInstance = Java.use("android.telephony.CellLocation");
	
		android_telephony_CellLocationInstance.getEmpty.overload().implementation = function() {
		const args = [].slice.call(arguments);
		console.log('getEmpty called with: ');
		console.log(args[0]);
		const result = this.getEmpty.overload().apply(this, args);
		console.log('Result: ' + result);
		return result;
	};
	
		var android_location_CountryInstance = Java.use("android.location.Country");
	
		android_location_CountryInstance.getCountryIso.overload().implementation = function() {
		const args = [].slice.call(arguments);
		console.log('getCountryIso called with: ');
		console.log(args[0]);
		const result = this.getCountryIso.overload().apply(this, args);
		console.log('Result: ' + result);
		return result;
	};
	
		var android_net_NetworkInfoInstance = Java.use("android.net.NetworkInfo");
	
		android_net_NetworkInfoInstance.getType.overload().implementation = function() {
		const args = [].slice.call(arguments);
		console.log('getType called with: ');
		console.log(args[0]);
		const result = this.getType.overload().apply(this, args);
		console.log('Result: ' + result);
		return result;
	};
		
			var connectivityManagerInstance = Java.use("android.net.ConnectivityManager");
			connectivityManagerInstance.getActiveNetworkInfo.overload().implementation = function() {
				const args = [].slice.call(arguments);
				console.log('getActiveNetworkInfo called');
				const result = this.getActiveNetworkInfo.overload().apply(this, args);
				console.log('Result: ');
				console.log(result.hashCode());
				return result;
			}

			var networkInfoInstance = Java.use("android.net.NetworkInfo");
			networkInfoInstance.isConnected.overload().implementation = function() {
				const args = [].slice.call(arguments);
				console.log('isConnected called');
				const result = this.isConnected.overload().apply(this, args);
				console.log('Result: ' + result);
				return result;
			}

		});
	}
	
