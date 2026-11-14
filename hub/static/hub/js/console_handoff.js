// Sends the one-time hand-off token on to the console origin as soon as the page has loaded.
// Without script the button on the page does the same.
document.addEventListener("DOMContentLoaded", function () {
  var form = document.getElementById("console-handoff");
  if (form) { form.submit(); }
});
