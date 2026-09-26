window.addEventListener('message', function (event) {
  if (event.origin !== 'https://trusted.example') return;
  event.source.postMessage('ack', event.origin);
});
