const getStartedButton = document.querySelector('.get-started-button');
const loginContainer = document.querySelector('.box');

getStartedButton.addEventListener('click', () => {
  loginContainer.scrollIntoView({ behavior: 'smooth' });
});

const createButton = document.getElementById('create-button');
createButton.addEventListener('click', () => {
  const username = document.getElementById('create-username').value;
  const bio = document.getElementById('create-bio').value;
  const password = document.getElementById('create-password').value;
  
  // Validate the input fields
  if (username === '' || bio === '' || password === '') {
    alert('Please fill in all the fields!');
    return;
  }
  
  // Create a new account
  localStorage.setItem('username', username);
  localStorage.setItem('bio', bio);
  localStorage.setItem('password', password);
  
  window.location.href = 'home.html';
});