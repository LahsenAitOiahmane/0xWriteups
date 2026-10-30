// KeyVault Pro - Client-side utilities
(function() {
  'use strict';

  // Auto-dismiss alerts after 5 seconds
  document.querySelectorAll('.alert-dismissible').forEach(function(alert) {
    setTimeout(function() {
      var bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
      bsAlert.close();
    }, 5000);
  });
})();
