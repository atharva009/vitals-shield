// Plain navigator.credentials with small base64url helpers (no @simplewebauthn). The server sends the WebAuthn
// library's {"publicKey": {...}} JSON; binary fields arrive as base64url and must become ArrayBuffers.

type Json = Record<string, unknown>;

function fromB64url(s: string): ArrayBuffer {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(s.length / 4) * 4, "=");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}

function toB64url(buf: ArrayBuffer | null | undefined): string | undefined {
  if (!buf) return undefined;
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function descriptors(list: unknown): PublicKeyCredentialDescriptor[] | undefined {
  if (!Array.isArray(list)) return undefined;
  return list.map((d: Json) => ({ ...(d as object), id: fromB64url(d.id as string) }) as PublicKeyCredentialDescriptor);
}

function publicKeyOf(options: Json): Json {
  return (options.publicKey as Json) ?? options;
}

/** navigator.credentials.create for {"publicKey": ...} creation options; returns the JSON the server parses. */
export async function createPasskey(options: Json): Promise<Json> {
  const pk = publicKeyOf(options);
  const user = pk.user as Json;
  const publicKey = {
    ...pk,
    challenge: fromB64url(pk.challenge as string),
    user: { ...user, id: fromB64url(user.id as string) },
    excludeCredentials: descriptors(pk.excludeCredentials),
  } as unknown as PublicKeyCredentialCreationOptions;
  const cred = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential | null;
  if (!cred) throw new Error("no credential created");
  const r = cred.response as AuthenticatorAttestationResponse;
  return {
    type: cred.type,
    id: cred.id,
    rawId: toB64url(cred.rawId),
    response: {
      clientDataJSON: toB64url(r.clientDataJSON),
      attestationObject: toB64url(r.attestationObject),
      transports: typeof r.getTransports === "function" ? r.getTransports() : [],
    },
    clientExtensionResults: cred.getClientExtensionResults(),
  };
}

/** navigator.credentials.get for {"publicKey": ...} request options (Touch ID prompt). */
export async function getAssertion(options: Json): Promise<Json> {
  const pk = publicKeyOf(options);
  const publicKey = {
    ...pk,
    challenge: fromB64url(pk.challenge as string),
    allowCredentials: descriptors(pk.allowCredentials),
  } as unknown as PublicKeyCredentialRequestOptions;
  const cred = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential | null;
  if (!cred) throw new Error("no assertion");
  const r = cred.response as AuthenticatorAssertionResponse;
  return {
    type: cred.type,
    id: cred.id,
    rawId: toB64url(cred.rawId),
    response: {
      clientDataJSON: toB64url(r.clientDataJSON),
      authenticatorData: toB64url(r.authenticatorData),
      signature: toB64url(r.signature),
      userHandle: toB64url(r.userHandle),
    },
    clientExtensionResults: cred.getClientExtensionResults(),
  };
}
