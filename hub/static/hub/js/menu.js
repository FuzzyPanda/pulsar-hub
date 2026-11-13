// Closes the account menu when the user presses Escape or clicks elsewhere.
(function () {
  "use strict";
  var menus = document.querySelectorAll("details.menu");
  if (!menus.length) return;
  document.addEventListener("click", function (event) {
    menus.forEach(function (menu) {
      if (menu.open && !menu.contains(event.target)) menu.open = false;
    });
  });
  document.addEventListener("keydown", function (event) {
    if (event.key !== "Escape") return;
    menus.forEach(function (menu) {
      if (menu.open) {
        menu.open = false;
        var summary = menu.querySelector("summary");
        if (summary) summary.focus();
      }
    });
  });
})();
