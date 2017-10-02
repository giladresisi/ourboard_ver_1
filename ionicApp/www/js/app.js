'use strict';

// Get the app name
var getAppName = function() {
	return 'starter';
};

// The app creation and retreival
var realApp = angular.module(getAppName(), appModules);
var app = angular.module(getAppName());

// Bootstrap the app to the desired location
var bootApp = function(bootLocation) {
	angular.bootstrap(bootLocation, [getAppName()]);
};