// Route & state config file

app
.config(function($stateProvider, $urlRouterProvider) {

  $stateProvider
    .state('app', {
      abstract: true,
      cache: false,
      templateUrl: 'templates/tabs.html',
      controller: 'AppCtrl'
    })
    .state('app.sessions', {
      cache: false,
      //url: '/sessions', ALPHA_NO_GROUPS
      url: '/',
      views: {
        'menuContent': {
          templateUrl: 'templates/sessions.html',
          controller: 'SessionsCtrl'
        }
      }
    });
    
  // if none of the above states are matched, use this as the fallback
  $urlRouterProvider.otherwise('/');
});