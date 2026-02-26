(function () {
  try {
    var serialized = localStorage.getItem('apexmail-ui') || '{}';
    var parsed = JSON.parse(serialized);
    var theme = (parsed && parsed.state && parsed.state.theme) || 'system';

    if (theme === 'system') {
      theme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    }

    if (theme === 'dark') {
      document.documentElement.classList.add('dark');
    }
  } catch (_) {
    // no-op
  }
})();
