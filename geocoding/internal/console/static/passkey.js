// Passkey ceremonies for the login and account pages (docs/auth.md
// "Passkeys"). Loaded as a file because the CSP allows no inline script.
(function () {
  "use strict";

  var loginBtn = document.getElementById("passkey-login");
  var registerBtn = document.getElementById("passkey-register");
  var errorEl = document.getElementById("passkey-error");
  if (!loginBtn && !registerBtn) {
    return;
  }

  if (!window.PublicKeyCredential || !navigator.credentials) {
    [loginBtn, registerBtn, document.getElementById("passkey-name"), document.querySelector('label[for="passkey-name"]')].forEach(function (el) {
      if (el) {
        el.hidden = true;
      }
    });
    showError("This browser does not support passkeys.");
    return;
  }

  function showError(msg) {
    if (!errorEl) {
      return;
    }
    errorEl.textContent = msg;
    errorEl.hidden = !msg;
  }

  function toBuffer(s) {
    var b64 = s.replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4) {
      b64 += "=";
    }
    var bin = atob(b64);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) {
      out[i] = bin.charCodeAt(i);
    }
    return out.buffer;
  }

  function toB64(buf) {
    var bytes = new Uint8Array(buf);
    var bin = "";
    for (var i = 0; i < bytes.length; i++) {
      bin += String.fromCharCode(bytes[i]);
    }
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function postJSON(url, body, csrf) {
    var headers = { "Content-Type": "application/json" };
    if (csrf) {
      headers["X-CSRF-Token"] = csrf;
    }
    return fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: headers,
      body: JSON.stringify(body || {}),
    }).then(function (res) {
      return res.json().catch(function () {
        return {};
      }).then(function (data) {
        if (!res.ok) {
          throw new Error(data.error || "The request failed. Try again.");
        }
        return data;
      });
    });
  }

  function descriptors(list) {
    return (list || []).map(function (c) {
      return { type: c.type, id: toBuffer(c.id), transports: c.transports };
    });
  }

  function failed(err) {
    if (err && err.name === "NotAllowedError") {
      showError("The passkey request was cancelled or timed out.");
    } else if (err && err.name === "InvalidStateError") {
      showError("This authenticator already holds a passkey for your account.");
    } else {
      showError((err && err.message) || "Something went wrong. Try again.");
    }
  }

  if (loginBtn) {
    loginBtn.addEventListener("click", function () {
      showError("");
      loginBtn.disabled = true;
      var state;
      postJSON("/auth/passkey/login/begin", { return_to: loginBtn.dataset.returnTo || "" })
        .then(function (data) {
          state = data.state;
          var pk = data.publicKey;
          pk.challenge = toBuffer(pk.challenge);
          pk.allowCredentials = descriptors(pk.allowCredentials);
          return navigator.credentials.get({ publicKey: pk });
        })
        .then(function (cred) {
          return postJSON("/auth/passkey/login/finish", {
            state: state,
            credential: {
              id: cred.id,
              rawId: toB64(cred.rawId),
              type: cred.type,
              response: {
                clientDataJSON: toB64(cred.response.clientDataJSON),
                authenticatorData: toB64(cred.response.authenticatorData),
                signature: toB64(cred.response.signature),
                userHandle: cred.response.userHandle ? toB64(cred.response.userHandle) : "",
              },
              clientExtensionResults: cred.getClientExtensionResults(),
            },
          });
        })
        .then(function (data) {
          window.location.assign(data.redirect || "/console");
        })
        .catch(failed)
        .finally(function () {
          loginBtn.disabled = false;
        });
    });
  }

  if (registerBtn) {
    registerBtn.addEventListener("click", function () {
      showError("");
      registerBtn.disabled = true;
      var csrf = registerBtn.dataset.csrf;
      var nameEl = document.getElementById("passkey-name");
      var state;
      postJSON("/console/account/passkeys/register/begin", {}, csrf)
        .then(function (data) {
          state = data.state;
          var pk = data.publicKey;
          pk.challenge = toBuffer(pk.challenge);
          pk.user.id = toBuffer(pk.user.id);
          pk.excludeCredentials = descriptors(pk.excludeCredentials);
          return navigator.credentials.create({ publicKey: pk });
        })
        .then(function (cred) {
          return postJSON("/console/account/passkeys/register/finish", {
            state: state,
            name: nameEl ? nameEl.value : "",
            credential: {
              id: cred.id,
              rawId: toB64(cred.rawId),
              type: cred.type,
              response: {
                clientDataJSON: toB64(cred.response.clientDataJSON),
                attestationObject: toB64(cred.response.attestationObject),
                transports: cred.response.getTransports ? cred.response.getTransports() : [],
              },
              clientExtensionResults: cred.getClientExtensionResults(),
            },
          }, csrf);
        })
        .then(function (data) {
          window.location.assign(data.redirect || "/console/account");
        })
        .catch(failed)
        .finally(function () {
          registerBtn.disabled = false;
        });
    });
  }
})();
