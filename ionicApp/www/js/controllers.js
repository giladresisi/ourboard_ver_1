angular.module('controllers', ['ion-datetime-picker', 'ngFileUpload'])

.controller('AppCtrl', function($scope, $auth, $http, $ionicModal, $ionicPopup, $state, $stateParams, $ionicNavBarDelegate, $ionicPopover, BACKEND_URL) {

  var unregisterOnStateChangeSuccess = null;

  $scope.user = {
    firstName: 'אורח'
  }

  $scope.comment = function() {
    $ionicPopup.confirm({
      title: 'כתבו לנו',
      content: "<center dir='rtl'>אהבתם? לא אהבתם?<br>יש משהו שחייבים לדעתכם להוסיף / לשנות / להוריד?<br>נשמח לשמוע! :)<br><br><textarea dir='rtl' rows='10' cols='30' style='resize:none' id='remark' placeholder='כתבו כאן'></textarea></center>",
      okText: 'שלח',
      cancelText: 'ביטול'
    })
      .then(function(res) {
        if (res) {
          var remarkText = document.getElementById('remark').value;
          if (remarkText.length == 0) {
            return;
          }
          var remarkObj = {
            remark: remarkText
          }
          $http({
            url: BACKEND_URL + 'remark',
            data: remarkObj,
            method: 'POST'
          });
        }
      });
  };

  $ionicPopover.fromTemplateUrl('templates/userMenu.html', {
    scope: $scope,
  }).then(function(popover) {
    $scope.userPopover = popover;
  });

  $ionicModal.fromTemplateUrl('templates/login.html', {
    scope: $scope
  }).then(function(modal) {
    $scope.loginModal = modal;
  });

  $ionicModal.fromTemplateUrl('templates/signup.html', {
    scope: $scope
  }).then(function(modal) {
    $scope.signupModal = modal;
  });

  $scope.closeLogin = function() {
    $scope.loginModal.hide()
      .then(function() {
        return;
      });
  };

  $scope.closeSignup = function() {
    $scope.signupModal.hide()
      .then(function() {
        return;
      });
  };

  $scope.loginToSignup = function() {
    $scope.closeLogin();
    $scope.signupData = {};
    $scope.signupModal.show()
      .then(function() {
        return;
      });
  };

  $scope.signupToLogin = function() {
    $scope.closeSignup();
    $scope.login();
  };

  $scope.login = function() {
    $scope.loginData = {};
    $scope.userPopover.hide()
      .then(function() {
        $scope.loginModal.show()
          .then(function() {
            return;
          });
      });
  };

  $scope.logout = function() {
    $auth.logout();
    $scope.userPopover.hide()
      .then(function() {
        unregisterOnStateChangeSuccess();
        $scope.removeBackdrops();
        $state.reload();
      });
  };

  // Perform the signup action when the user submits the signup form
  $scope.doSignup = function() {
    $auth.signup($scope.signupData)
      .then(function(response) {
        $auth.setToken(response);
        $scope.closeSignup();
        unregisterOnStateChangeSuccess();
        $scope.removeBackdrops();
        $state.reload();
      });
  };  

  // Perform the login action when the user submits the login form
  $scope.doLogin = function() {
    $auth.login($scope.loginData)
      .then(function() {
        $scope.closeLogin();
        unregisterOnStateChangeSuccess();
        $scope.removeBackdrops();
        $state.reload();
      });
  };

  // Authenticate current visitor with external auth provider
  $scope.authenticate = function(provider) {
    $auth.authenticate(provider)
      .then(function() {
        $scope.closeLogin();
        unregisterOnStateChangeSuccess();
        $scope.removeBackdrops();
        $state.reload();
      });
  };

  // Check if the current visitor is an authenticated user
  $scope.isAuthenticated = function() {
    return $auth.isAuthenticated();
  };

  $scope.onStateChangeSuccess = function(event, toState, toParams, fromState, fromParams) {
    if ($scope.isAuthenticated()) {
      $http.get(BACKEND_URL + 'user/basic')
        .then(function(response) {
          $scope.user = response.data;
          $scope.user.firstName = $scope.user.displayName;
          var firstSpaceIndex = $scope.user.firstName.indexOf(" ");
          if (firstSpaceIndex != -1) {
            $scope.user.firstName = $scope.user.firstName.substring(0, firstSpaceIndex);
          }
        })
        .catch(function(err) {
          console.log('Error get(/user/basic): ' + JSON.stringify(err) + ', logging out...');
          $scope.logout();
        });
    } else {
      $scope.user.firstName = 'אורח';
    }
  };

  $scope.removeBackdrops = function() {
    if ($scope.loginModal) {
      $scope.loginModal.remove()
        .then(function() {
          $scope.loginModal = null;
        });
    }
    if ($scope.signupModal) {
      $scope.signupModal.remove()
        .then(function() {
          $scope.signupModal = null;
        });
    }
    if ($scope.userPopover) {
      $scope.userPopover.remove()
        .then(function() {
          $scope.userPopover = null;
        });
    }
  };

  $scope.reload = function() {
    unregisterOnStateChangeSuccess();
    $scope.removeBackdrops();
    $state.reload();
  };

  $scope.$on('$ionicView.enter', function(e) {
    $ionicNavBarDelegate.showBar(true);
  });

  $scope.$on('$stateChangeStart', function() {
    $scope.removeBackdrops();
  });

  unregisterOnStateChangeSuccess = $scope.$on('$stateChangeSuccess', $scope.onStateChangeSuccess);
})

.controller('SessionsCtrl', function($scope, Upload, $auth, $http, $state, $ionicPopup, $ionicModal, $filter, ACTIVITY_TYPES, BACKEND_URL, S3_BUCKET_PREFIX) {

  $scope.url = S3_BUCKET_PREFIX + 'ionic.png';

  // Local vars
  $scope.sessions = [];
  $scope.showMineOnly = false;
  $scope.activityTypes = ACTIVITY_TYPES;
  $scope.loaded = false;

  $ionicModal.fromTemplateUrl('templates/login.html', {
    scope: $scope
  }).then(function(modal) {
    $scope.loginModal = modal;
  });

  $ionicModal.fromTemplateUrl('templates/signup.html', {
    scope: $scope
  }).then(function(modal) {
    $scope.signupModal = modal;
  });

  $scope.closeLogin = function() {
    $scope.loginModal.hide()
      .then(function() {
        return;
      });
  };

  $scope.closeSignup = function() {
    $scope.signupModal.hide()
      .then(function() {
        return;
      });
  };

  $scope.loginToSignup = function() {
    $scope.closeLogin();
    $scope.signupData = {};
    $scope.signupModal.show()
      .then(function() {
        return;
      });
  };

  $scope.signupToLogin = function() {
    $scope.closeSignup();
    $scope.login();
  };

  $scope.login = function() {
    $scope.loginData = {};
    $scope.loginModal.show()
      .then(function() {
        return;
      });
  };

  // Perform the signup action when the user submits the signup form
  $scope.doSignup = function() {
    $auth.signup($scope.signupData)
      .then(function(response) {
        $auth.setToken(response);
        $scope.closeSignup();
        $scope.removeBackdrops();
        $state.reload();
      });
  };  

  // Perform the login action when the user submits the login form
  $scope.doLogin = function() {
    $auth.login($scope.loginData)
      .then(function() {
        $scope.closeLogin();
        $scope.removeBackdrops();
        $state.reload();
      });
  };

  // Authenticate current visitor with external auth provider
  $scope.authenticate = function(provider) {
    $auth.authenticate(provider)
      .then(function() {
        $scope.closeLogin();
        $scope.removeBackdrops();
        $state.reload();
      });
  };

  $ionicModal.fromTemplateUrl('templates/newSession.html', {
    scope: $scope
  }).then(function(modal) {
    $scope.newSessionModal = modal;
  });

  // Triggered in the login modal to close it
  $scope.closeNewSessionModal = function() {
    $scope.newSessionModal.hide()
      .then(function() {
        return;
      });
  };

  // Open the login modal
  $scope.showNewSessionModal = function() {
    $scope.yearFromNow = new Date();
    $scope.yearFromNow.setFullYear($scope.yearFromNow.getFullYear() + 1);
    $scope.newSessionImg = undefined;
    $scope.newSession = {};
    $scope.newSession.type = "<בחר או הקלד סוג פעילות>";
    $scope.newSession.location = '';
    $scope.newSession.extraDetails = '';
    $scope.newSessionModal.show()
      .then(function() {
        return;
      });
  };

  $scope.onImgSelect = function(file) {
    $scope.newSessionImg = file;
    if (file) {
      console.log('filename: ' + file.name);
    }
  };

  // Perform the login action when the user submits the login form
  $scope.createNewSession = function() {
    if ((!$scope.newSession.location) || ($scope.newSession.location == '')) {
      $ionicPopup.alert({
        title: 'מיקום לא תקין',
        content: "<center>הקלד מיקום לפעילות</center>"
      });
      return;
    }
    if ($scope.newSession.location.length > 40) {
      $ionicPopup.alert({
        title: 'מיקום לא תקין',
        content: "<center>אורך מחרוזת המיקום חייב להיות 15 תווים לכל היותר</center>"
      });
      return;
    }
    if (!$scope.newSession.datetime) {
      $ionicPopup.alert({
        title: 'תאריך ושעה לא תקינים',
        content: "<center>בחר תאריך ושעה לפעילות</center>"
      });
      return;
    }
    if (($scope.newSession.datetime < new Date()) || ($scope.newSession.datetime.getTime() > $scope.yearFromNow.getTime())) {
      $ionicPopup.alert({
        title: 'תאריך ושעה לא תקינים',
        content: "<center>זמן הפעילות חייב להיות בעתיד ובשנה הקרובה</center>"
      });
      return;
    }
    if ($scope.newSession.type == '<בחר או הקלד סוג פעילות>') {
      $ionicPopup.alert({
        title: 'סוג פעילות לא תקין',
        content: "<center>בחר או הקלד סוג פעילות</center>"
      });
      return;
    }
    if ($scope.newSession.type.length > 18) {
      $ionicPopup.alert({
        title: 'סוג פעילות לא תקין',
        content: "<center>אורך מחרוזת סוג הפעילות חייב להיות 15 תווים לכל היותר</center>"
      });
      return;
    }

    $scope.newSession.datetimeMS = $scope.newSession.datetime.getTime();
    delete $scope.newSession.datetime;

    var fd = new FormData();

    $scope.newSession.hasImage = false;
    if ($scope.newSessionImg != undefined) {
      $scope.newSession.hasImage = true;
      $scope.newSession.imgName = $scope.newSessionImg.name;
      fd.append('imgName', $scope.newSession.imgName);
      fd.append('file', $scope.newSessionImg);
    }

    fd.append('location', $scope.newSession.location);
    fd.append('type', $scope.newSession.type);
    fd.append('hasImage', $scope.newSession.hasImage);
    fd.append('extraDetails', $scope.newSession.extraDetails);
    fd.append('datetimeMS', $scope.newSession.datetimeMS);

    var options = {
      withCredentials: false,
      headers: {
        'Content-Type': undefined
      },
      transformRequest: angular.identity
    };

    $http.post(
      BACKEND_URL + 'session/create',
      fd,
      options
    )
      .then(function(response) {
        $scope.closeNewSessionModal();
        var s = response.data;
        s.datetime = new Date(Number(s.datetimeMS));
        s.dateStr = $filter('date')(s.datetime, "dd/MM");
        s.timeStr = $filter('date')(s.datetime, "H:mm");
        console.log('s: ' + JSON.stringify(s));
        var i = $scope.sessions.findIndex(function(session) {
          return (session.datetimeMS > s.datetimeMS);
        });
        if (i != -1) {
          $scope.sessions.splice(i, 0, s);
          $scope.showSessionInfo($scope.sessions[i]);
        } else {
          $scope.sessions.push(s);
          $scope.showSessionInfo($scope.sessions[$scope.sessions.length - 1]);
        }
      })
      .catch(function(message, status) {
        console.log('Create session error - status: ' + status + ', message: ' + message);
      });
  };

  $scope.isAuthenticated = function() {
    return $auth.isAuthenticated();
  };

  function sessionIsSelectedWithParticipants(session) {
    return ($scope.selectedSession &&
            ($scope.selectedSession._id.toString() == session._id.toString()) &&
            $scope.selectedSession.participants);
  }

  $scope.onParticipationChange = function(session) {
    if (session.isParticipant) {
      session.nParticipants += 1;
      $http({
        url: BACKEND_URL + 'session/join',
        data: {sessionId: session._id},
        method: 'POST'
      })
        .then(function(response) {
          if (sessionIsSelectedWithParticipants(session)) {
            $scope.selectedSession.participants.push(response.data);
          }
        });
    } else if (session.isOrganizer) {
      $ionicPopup.confirm({
        title: 'בטוח? אתה המארגן',
        template: "<center>אם לא תאשר הגעה הפעילות כולה תתבטל</center>"
      })
        .then(function(res) {
          if (!res) {
            session.isParticipant = true;
            return;
          } else {
            $scope.sessions.splice($scope.sessions.findIndex(function(s) {
              return (s._id.toString() == session._id.toString());
            }), 1);
            $scope.closeSessionParticipants();
            $scope.closeSessionInfo();
            $http({
              url: BACKEND_URL + 'session/leave',
              data: {sessionId: session._id, isOrganizer: true},
              method: 'POST'
            });
          }
        });
    } else {
      session.nParticipants -= 1;
      if (sessionIsSelectedWithParticipants(session)) {
        $scope.selectedSession.participants =
          $scope.selectedSession.participants.filter(function(participant) {
            return (participant._id.toString() != $scope.userId);
          });
      }
      $http({
        url: BACKEND_URL + 'session/leave',
        data: {sessionId: session._id, isOrganizer: false},
        method: 'POST'
      });
    }
  }

  $ionicModal.fromTemplateUrl('templates/sessionInfo.html', {
    scope: $scope
  }).then(function(modal) {
    $scope.sessionInfoModal = modal;
  });

  $scope.showSessionInfo = function(session) {
    $scope.closeSessionParticipants();
    if (!$scope.selectedSession ||
        ($scope.selectedSession._id.toString() != session._id.toString())) {
      $scope.selectedSession = session;
    }
    $scope.sessionInfoModal.show()
      .then(function() {
        if ($scope.selectedSession.hasImage) {
          var endPoint = BACKEND_URL + 'session/single';
          if ($scope.isAuthenticated()) {
            endPoint += '/user';
          }
          $http.get(endPoint, {
            params: {sessionId: $scope.selectedSession._id.toString()}
          })
            .then(function(response) {
              $scope.selectedSession.imageUrl = S3_BUCKET_PREFIX + $scope.selectedSession._id.toString() + '/' + response.data.imgName;
            });
        }
      });
  };

  $scope.closeSessionInfo = function() {
    if ($scope.sessionInfoModal.isShown()) {
      $scope.sessionInfoModal.hide()
        .then(function() {
          return;
        });
    }
  };

  $ionicModal.fromTemplateUrl('templates/sessionParticipants.html', {
    scope: $scope
  }).then(function(modal) {
    $scope.sessionParticipantsModal = modal;
  });

  $scope.showSessionParticipants = function(session) {
    $scope.closeSessionInfo();
    if (!$scope.selectedSession ||
        ($scope.selectedSession._id.toString() != session._id.toString())) {
      $scope.selectedSession = session;
    }
    $scope.sessionParticipantsModal.show()
      .then(function() {
        if (!$scope.selectedSession.participants) {
          var endPoint = BACKEND_URL + 'session/single';
          if ($scope.isAuthenticated()) {
            endPoint += '/user';
          }
          $http.get(endPoint, {
            params: {sessionId: $scope.selectedSession._id.toString()}
          })
            .then(function(response) {
              $scope.selectedSession.participants = response.data.participants;
            });
        }
      });
  };

  $scope.closeSessionParticipants = function() {
    if ($scope.sessionParticipantsModal.isShown()) {
      $scope.sessionParticipantsModal.hide()
        .then(function() {
          return;
        });
    }
  };

  $scope.backToSessionInfo = function() {
    $scope.closeSessionParticipants();
    $scope.sessionInfoModal.show()
      .then(function() {
        return;
      });
  };

  $scope.sessionIcon = function(session) {
    if (session.isOrganizer) {
      return 'icon ion-android-people balanced';
    } else {
      return 'icon ion-android-people positive';
    }
  };

  $scope.goToLink = function(url) {
    window.open(url, '_system', 'location=yes');
  };

  $scope.removeBackdrops = function() {
    if ($scope.newSessionModal) {
      $scope.newSessionModal.remove()
        .then(function() {
          $scope.newSessionModal = null;
        });
    }
    if ($scope.sessionInfoModal) {
      $scope.sessionInfoModal.remove()
        .then(function() {
          $scope.sessionInfoModal = null;
        });
    }
    if ($scope.sessionParticipantsModal) {
      $scope.sessionParticipantsModal.remove()
        .then(function() {
          $scope.sessionParticipantsModal = null;
        });
    }
    if ($scope.loginModal) {
      $scope.loginModal.remove()
        .then(function() {
          $scope.loginModal = null;
        });
    }
    if ($scope.signupModal) {
      $scope.signupModal.remove()
        .then(function() {
          $scope.signupModal = null;
        });
    }
  };

  $scope.$on('$stateChangeStart', function() {
    $scope.removeBackdrops();
  });

  var endPoint = BACKEND_URL + 'session/all';

  if ($scope.isAuthenticated()) {
    endPoint += '/user';
    $scope.userId = $auth.getPayload().sub.toString();
  }

  console.log("Sessions loading");

  $http.get(endPoint)
    .then(function(response) {
      console.log("Sessions loaded");
      $scope.loaded = true;
      $scope.sessions = response.data;
      $scope.sessions.forEach(function(session, index, arr) {
        arr[index].datetime = new Date(session.datetimeMS);
        arr[index].dateStr = $filter('date')(arr[index].datetime, "dd/MM");
        arr[index].timeStr = $filter('date')(arr[index].datetime, "H:mm");
      });
    });
});