/* Theme before first paint: default light (BloodHound CE style), persist choice.
   External file (no inline scripts: the workbench CSP is script-src 'self'). */
(function () {
  var th = localStorage.getItem("serket.theme");
  document.documentElement.dataset.theme = (th === "dark" || th === "light") ? th : "light";
})();
