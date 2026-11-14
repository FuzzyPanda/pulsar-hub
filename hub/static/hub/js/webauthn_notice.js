// Security key and passkey pages (templates/mfa/webauthn/snippets/scripts.html). django-allauth's
// own script reports a failed attempt with an "allauth.error" event and otherwise only writes to
// the console, which leaves the person looking at a button that did nothing. This says why.
(function () {
  "use strict";
  var notice = document.getElementById("webauthn_notice");
  if (!notice) return;
  document.addEventListener("allauth.error", function () {
    if (!window.isSecureContext || !window.PublicKeyCredential) {
      notice.textContent =
        "Security keys and passkeys only work over a secure (https) connection, and this page was " +
        "opened without one. Use an authenticator app instead.";
    } else {
      notice.textContent =
        "The security key was not used. Try again, or use an authenticator app or a recovery code instead.";
    }
    notice.hidden = false;
  });
})();
