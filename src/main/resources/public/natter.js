const apiUrl = "https://localhost:4567";

window.addEventListener("load", (e) => {
  let form = document.getElementById("createSpace");
  form.addEventListener("submit", processFormSubmit);
});

function processFormSubmit(e) {
  e.preventDefault();

  let spaceName = document.getElementById("spaceName").value;
  let owner = document.getElementById("owner").value;

  createSpace(spaceName, owner);

  return false;
}

function createSpace(name, owner) {
  let data = {
    name: name,
    owner: owner,
  };

  fetch(apiUrl + "/spaces", {
    method: "POST",
    credentials: "include",
    body: JSON.stringify(data),
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": getCookie("csrfToken"),
    },
  })
    .then((response) => {
      if (response.ok) {
        return response.json();
      } else if (response.status === 401) {
        window.location.replace("/login.html");
      } else {
        throw new Error("empty response");
      }
    })
    .then((json) => {
      console.log(`Create space: ${json.name}, ${json.uri}`);
    })
    .catch((error) => console.error("Error: ", error));
}

function getCookie(cookieName) {
  var cookie = document.cookie
    .split(";")
    .map((item) => item.split("=").map((x) => decodeURIComponent(x.trim())))
    .filter((item) => item[0] == cookieName)[0];

  if (cookie) {
    return cookie[1];
  }
}
