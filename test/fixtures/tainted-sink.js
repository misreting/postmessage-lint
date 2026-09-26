window.addEventListener('message', function (event) {
  if (event.origin !== 'https://trusted.example') return;
  const payload = event.data;
  document.getElementById('out').innerHTML = payload;
});
