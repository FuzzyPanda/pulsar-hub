// The recovery codes page (templates/mfa/recovery_codes/index.html). The page works without this
// script; with it, "Continue" stays disabled until the box is ticked, the codes can be copied, and
// leaving before the box is ticked asks first, because the codes are shown only once.
(function () {
  "use strict";
  var saved = document.getElementById("codes_saved");
  var go = document.getElementById("codes_continue");
  var codes = document.getElementById("recovery_codes");
  var copy = document.getElementById("codes_copy");
  var status = document.getElementById("codes_copy_status");

  function warn(event) {
    event.preventDefault();
    event.returnValue = "";
  }

  if (saved && go) {
    var sync = function () {
      go.disabled = !saved.checked;
      if (saved.checked) {
        window.removeEventListener("beforeunload", warn);
      } else {
        window.addEventListener("beforeunload", warn);
      }
    };
    // A form with no named fields would otherwise leave a bare "?" on the address it goes to.
    var form = go.form;
    if (form) {
      form.addEventListener("submit", function (event) {
        event.preventDefault();
        window.location.assign(form.getAttribute("action"));
      });
    }
    saved.addEventListener("change", sync);
    // A page restored from the browser's history can come back with the box already ticked.
    window.addEventListener("pageshow", sync);
    sync();
  }

  function say(text) {
    if (status) status.textContent = text;
  }

  function copyCodes() {
    var text = codes.value;
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(
        function () { say("Copied."); },
        function () { fallbackCopy(); }
      );
    } else {
      fallbackCopy();
    }
  }

  // Plain-HTTP lab hubs have no clipboard API: select the text and use the older command.
  function fallbackCopy() {
    codes.focus();
    codes.select();
    var done = false;
    try {
      done = document.execCommand("copy");
    } catch (error) {
      done = false;
    }
    say(done ? "Copied." : "The codes are selected. Press Ctrl+C or Cmd+C to copy them.");
  }

  if (codes) {
    codes.addEventListener("focus", function () { codes.select(); });
    if (copy) {
      copy.hidden = false;
      copy.addEventListener("click", copyCodes);
    }
  }
})();
