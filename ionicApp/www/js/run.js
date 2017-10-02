// Run (main app module function) file

app
.run(function($ionicPlatform, $ionicPickerI18n) {
  $ionicPlatform.ready(function() {
    // Hide the accessory bar by default (remove this to show the accessory bar above the keyboard
    // for form inputs)
    if (window.cordova && window.cordova.plugins.Keyboard) {
      cordova.plugins.Keyboard.hideKeyboardAccessoryBar(true);
      cordova.plugins.Keyboard.disableScroll(true);

    }
    if (window.StatusBar) {
      // org.apache.cordova.statusbar required
      StatusBar.styleDefault();
    }
  });

  $ionicPickerI18n.weekdays = ["א'", "ב'", "ג'", "ד'", "ה'", "ו'", "ש'"];
  $ionicPickerI18n.months = ["ינואר", "פברואר", "מרץ", "אפריל", "מאי", "יוני", "יולי", "אוגוסט", "ספטמבר", "אוקטובר", "נובמבר", "דצמבר"];
  $ionicPickerI18n.ok = "אישור";
  $ionicPickerI18n.cancel = "ביטול";
});
