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
  let token = window.localStorage.getItem("token");

  fetch(apiUrl + "/spaces", {
    method: "POST",
    body: JSON.stringify(data),
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
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
