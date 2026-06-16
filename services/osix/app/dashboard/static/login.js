const form = document.getElementById("osixLogin");
const status = document.getElementById("loginStatus");

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  status.textContent = "Перевіряю...";
  const data = new FormData(form);
  const response = await fetch("/osix/api/v1/admin/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify({
      username: data.get("username"),
      password: data.get("password"),
    }),
  });
  if (!response.ok) {
    status.textContent = response.status === 503 ? "OSIX admin auth не налаштовано." : "Невірний логін або пароль.";
    return;
  }
  window.location.assign("/osix");
});

