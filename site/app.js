// The page code lives in js/main.js, loaded by index.html as a module. This file stays for
// one case: a browser that cached the earlier index.html, which loaded ./app.js. That page
// reloads once (a session flag prevents a loop) so the browser reads the current index.html.
(function () {
  "use strict";
  if (document.documentElement.hasAttribute("data-hub-shell")) return;
  try {
    if (window.sessionStorage.getItem("tsw-hub-reloaded")) return;
    window.sessionStorage.setItem("tsw-hub-reloaded", "earlier-page");
  } catch (error) {
    return;
  }
  window.location.reload();
})();
