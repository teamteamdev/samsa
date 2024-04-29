async function register() {
    const getResponse = await fetch("/passkey/enroll", {
        headers: {
            "Accept": "application/json"
        }
    });
    const publicKey = await getResponse.json();

    let credentialJSON;

    try {
        if (PublicKeyCredential.parseCreationOptionsFromJSON !== undefined) {
            const creationOptions = { publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(publicKey) };
            const creds = await navigator.credentials.create(creationOptions);
            credentialJSON = creds.toJSON();
        } else {
            // use polyfill
            credentialJSON = await webauthnJSON.create({ publicKey });
        }
    } catch (err) {
        alert("Не удалось добавить ключ: " + err);
        return;
    }

    const postResponse = await fetch("/passkey/enroll", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Accept": "application/json"
        },
        body: JSON.stringify(credentialJSON)
    });

    if (postResponse.status !== 200) {
        const error = await postResponse.json();
        alert('Не удалось добавить ключ: ' + error.error);
    } else {
        document.location.reload();
    }
}

async function login() {
    const getResponse = await fetch("/sso/passkey", {
        headers: {
            "Accept": "application/json"
        }

    });
    const publicKey = await getResponse.json();

    let credentialJSON;

    try {
        if (PublicKeyCredential.parseRequestOptionsFromJSON !== undefined) {
            const requestOptions = { publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(publicKey) };
            const creds = await navigator.credentials.get(requestOptions);
            credentialJSON = creds.toJSON();
        } else {
            // use polyfill
            credentialJSON = await webauthnJSON.get({ publicKey });
        }
    } catch (err) {
        alert("Не удалось получить ключ: " + err);
        return;
    }

    const postResponse = await fetch("/sso/passkey", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Accept": "application/json"
        },
        body: JSON.stringify(credentialJSON)
    });

    if (postResponse.status !== 200) {
        const error = await postResponse.json();
        alert('Не удалось авторизоваться: ' + error.error);
    } else {
        document.location.reload();
    }
}
