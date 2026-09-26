interface Payload {
  kind: string;
}

window.addEventListener('message', (event: MessageEvent<Payload>) => {
  if (event.origin !== 'https://trusted.example') return;
  console.log(event.data.kind);
});
