// Auth config file

app
.config(function($authProvider, BACKEND_URL, FACEBOOK_CLIENT_ID, GOOGLE_CLIENT_ID) {
  var commonConfig = {
    popupOptions: {
      location: 'no',
      toolbar: 'yes',
      width: window.screen.width,
      height: window.screen.height
    }
  };

  var commonConfigSlash = angular.extend({}, commonConfig);

  var urlPrefix = '/';

  if (window.cordova !== undefined) {
    commonConfig.redirectUri = 'http://localhost:3000';
    commonConfigSlash.redirectUri = commonConfig.redirectUri + '/';
    urlPrefix = BACKEND_URL;
    $authProvider.baseUrl = BACKEND_URL;
  }

  $authProvider.facebook(angular.extend({}, commonConfigSlash, {
    clientId: FACEBOOK_CLIENT_ID,
    url: urlPrefix + 'auth/facebook'
  }));

  $authProvider.twitter(angular.extend({}, commonConfig, {
    url: urlPrefix + 'auth/twitter'
  }));

  $authProvider.google(angular.extend({}, commonConfig, {
    clientId: GOOGLE_CLIENT_ID,
    url: urlPrefix + 'auth/google'
  }));
});