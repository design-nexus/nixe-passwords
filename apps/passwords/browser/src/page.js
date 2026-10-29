// Runs in the page's own world, only when passkeys are turned on in Nyx Passwords:
// `navigator.credentials.create` and `.get` for public keys go to Nyx Passwords first.
// The request passes through the content script to the extension, which builds the
// client data from the frame's real origin and asks the user in its own window. When
// the user picks the browser instead, or nothing is saved, the browser's own runs.

(() => {
  const credentials = navigator.credentials;
  if (!credentials || window.__nyxWebAuthn) return;
  window.__nyxWebAuthn = true;
  const originalGet = credentials.get.bind(credentials);
  const originalCreate = credentials.create.bind(credentials);

  const b64url = (buffer) => {
    const bytes = buffer instanceof ArrayBuffer ? new Uint8Array(buffer) : new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };
  const bytes = (text) => {
    const s = atob(text.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((text.length + 3) % 4));
    return Uint8Array.from(s, (c) => c.charCodeAt(0)).buffer;
  };

  let next = 0;
  function ask(kind, options) {
    const id = `${Date.now()}-${next++}`;
    return new Promise((resolve) => {
      const listen = (e) => {
        if (e.source !== window || e.data?.nyx !== "webauthn-reply" || e.data.id !== id) return;
        window.removeEventListener("message", listen);
        resolve(e.data.answer);
      };
      window.addEventListener("message", listen);
      window.postMessage({ nyx: "webauthn", id, kind, options }, location.origin);
    });
  }

  function credential(kind, c) {
    const rawId = bytes(c.id);
    const clientDataJSON = bytes(c.clientDataJSON);
    const response =
      kind === "get"
        ? Object.setPrototypeOf(
            { clientDataJSON, authenticatorData: bytes(c.authenticatorData), signature: bytes(c.signature), userHandle: c.userHandle ? bytes(c.userHandle) : null },
            AuthenticatorAssertionResponse.prototype,
          )
        : Object.setPrototypeOf(
            {
              clientDataJSON,
              attestationObject: bytes(c.attestationObject),
              getTransports: () => ["internal", "hybrid"],
              getAuthenticatorData: () => bytes(c.authenticatorData),
              getPublicKey: () => null,
              getPublicKeyAlgorithm: () => c.algorithm,
            },
            AuthenticatorAttestationResponse.prototype,
          );
    const out = {
      id: c.id,
      rawId,
      type: "public-key",
      authenticatorAttachment: "platform",
      response,
      getClientExtensionResults: () => ({}),
      toJSON: () => ({
        id: c.id,
        rawId: c.id,
        type: "public-key",
        authenticatorAttachment: "platform",
        clientExtensionResults: {},
        response:
          kind === "get"
            ? { clientDataJSON: c.clientDataJSON, authenticatorData: c.authenticatorData, signature: c.signature, userHandle: c.userHandle }
            : { clientDataJSON: c.clientDataJSON, attestationObject: c.attestationObject, transports: ["internal", "hybrid"], authenticatorData: c.authenticatorData, publicKeyAlgorithm: c.algorithm },
      }),
    };
    return Object.setPrototypeOf(out, PublicKeyCredential.prototype);
  }

  // Only what the extension needs, as text: the rest of the request stays here.
  function plain(kind, pk) {
    const ids = (list) => (list ?? []).map((c) => ({ id: b64url(c.id), type: c.type }));
    return kind === "get"
      ? { challenge: b64url(pk.challenge), rpId: pk.rpId, allowCredentials: ids(pk.allowCredentials), userVerification: pk.userVerification }
      : {
          challenge: b64url(pk.challenge),
          rp: { id: pk.rp?.id, name: pk.rp?.name },
          user: { id: b64url(pk.user.id), name: pk.user.name, displayName: pk.user.displayName },
          excludeCredentials: ids(pk.excludeCredentials),
          authenticatorSelection: pk.authenticatorSelection ?? {},
          supportsES256: (pk.pubKeyCredParams ?? []).some((p) => p.alg === -7),
        };
  }

  async function handle(kind, options, original) {
    const pk = options?.publicKey;
    // Autofill-style requests and sites that don't take ES256 stay with the browser.
    if (!pk || options.mediation === "conditional" || (kind === "create" && !(pk.pubKeyCredParams ?? []).some((p) => p.alg === -7))) {
      return original(options);
    }
    const answer = await ask(kind, plain(kind, pk));
    if (answer?.credential) return credential(kind, answer.credential);
    if (answer?.fallback) return original(options);
    throw new DOMException("The operation either timed out or was not allowed.", "NotAllowedError");
  }

  credentials.get = (options) => handle("get", options, originalGet);
  credentials.create = (options) => handle("create", options, originalCreate);
})();
