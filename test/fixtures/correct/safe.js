const TRUSTED_ORIGINS = ['https://trusted.example', 'https://trusted-2.example'];

window.addEventListener('message', function (event) {
  if (!TRUSTED_ORIGINS.includes(event.origin)) return;
  if (event.source !== embeddedFrame.contentWindow) return;

  const text = document.createTextNode(String(event.data));
  document.getElementById('out').appendChild(text);

  event.source.postMessage('ack', event.origin);
});

function sendToFrame(frame, message) {
  frame.contentWindow.postMessage(message, 'https://trusted.example');
}
