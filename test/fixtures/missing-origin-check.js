window.addEventListener('message', function (event) {
  console.log('got', event.data);
  doSomething(event.data);
});
