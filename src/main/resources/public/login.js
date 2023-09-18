const apiUrl = "https://localhost:4567";

window.addEventListener("load", function (e) {
  document
    .getElementById("login")
    .addEventListener("submit", processLoginSubmit);
});

function processLoginSubmit(e) {
  e.preventDefault();

  let username = document.getElementById("username").value;
  let password = document.getElementById("password").value;

  login(username, password);
}

function login(username, password) {
  let credentials = `Basic ${btoa(username + ":" + password)}`;
  fetch(`${apiUrl}/sessions`, {
    method: "POST",
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      Authorization: credentials,
    },
  })
    .then((response) => {
      if (response.ok) {
        return response.json().then((json) => {
          document.cookie = `csrfToken=${json.token};Secure;SameSite=strict`;
          window.location.replace("/natter.html");
        });
      }
    })

    .catch((error) => console.error(`Error logging in: ${error}`));
}
