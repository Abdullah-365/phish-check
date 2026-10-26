(function () {
  var theme = "dark";
  try {
    var saved = localStorage.getItem("phish-check:theme");
    if (saved === "light" || saved === "dark") theme = saved;
    else if (matchMedia("(prefers-color-scheme: light)").matches) theme = "light";
  } catch (e) {
    // Storage can be blocked; the system preference is still a fine default.
  }
  document.documentElement.dataset.theme = theme;
})();
