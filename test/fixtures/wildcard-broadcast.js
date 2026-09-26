// A handler that checks its origin correctly, next to a broadcast that doesn't.
window.addEventListener('message', function (event) {
  if (event.origin !== 'https://trusted.example') return;
  console.log(event.data);
});

function broadcast(win, payload) {
  win.postMessage(payload, '*');
}
