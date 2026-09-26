window.addEventListener('message', (event) => {
  // "https://evil-yoursite.com".includes('yoursite.com') is also true.
  if (event.origin.includes('yoursite.com')) {
    handle(event.data);
  }
});
