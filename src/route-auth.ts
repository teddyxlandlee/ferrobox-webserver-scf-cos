import {Hono} from "hono";
import {getAllScopes, newAccessToken, Scope} from "./access-token.js";
import {uuidv7} from "uuidv7-js";
import {assert} from "./assert.js";
import * as jwt from 'jsonwebtoken'
import * as crypto from 'node:crypto'
import {Buffer} from 'node:buffer'

const authRoute = new Hono({
    strict: false
})

interface ChallengePayload {
    scopes: Scope[],
    nonce: ReturnType<typeof uuidv7>,
}

const TTL = '60s'

const JWT_AUTH_CHALLENGE = Buffer.from(process.env.JWT_AUTH_CHALLENGE || '', 'base64')
assert(JWT_AUTH_CHALLENGE.length > 0, 'JWT_AUTH_CHALLENGE is empty')

// ─── Root CA ──────────────────────────────────────────────────────────────

type RootCA = crypto.X509Certificate

const ROOT_CA_PEM = process.env.ROOT_CA_PEM ?? ''
assert(!!ROOT_CA_PEM, 'ROOT_CA_PEM is empty')

const rootCA: RootCA = new crypto.X509Certificate(ROOT_CA_PEM)

function signChallenge(payload: ChallengePayload): string {
    return jwt.sign(payload, JWT_AUTH_CHALLENGE, {
        expiresIn: TTL,
        keyid: 'challenge',
    })
}

function verifyChallenge(token: string): null | ChallengePayload {
    try {
        const payload = jwt.verify(token, JWT_AUTH_CHALLENGE)
        if (typeof payload === 'string') return null    // invalid
        return {
            scopes: payload.scopes,
            nonce: payload.nonce
        }
    } catch {
        return null
    }
}

authRoute.get('/', (c) => {
    if (c.req.header('Authorization')) {
        // You shouldn't have been here
        return c.text('Authorization header not allowed', {status: 400})
    }
    // start auth challenge
    const allScopes = getAllScopes()
    let scopes = c.req.query('scope')
        ?.split(/\s+/)
        ?.filter((k) => (allScopes.includes(k as Scope))) as Scope[] | undefined
    if (!scopes || !scopes.length) scopes = allScopes

    const challengePayload: ChallengePayload = {
        scopes,
        nonce: uuidv7(),
    }
    return c.text(signChallenge(challengePayload), {
        headers: {
            'Content-Type': "application/jwt",
        }
    })
})

// ─── SignResult schema (mirrors client-side types) ────────────────────────

interface WebCryptoSignResult {
    type: 'webcrypto'
    signature: string       // base64
    certs: string[]         // PEM certificates
}

interface WebAuthnSignResult {
    type: 'webauthn'
    credentialId: string     // base64
    clientDataJSON: string   // base64
    authenticatorData: string // base64
    signature: string        // base64
    userHandle: string | null // base64
    certs: string[]          // PEM certificates
}

type SignResult = WebCryptoSignResult | WebAuthnSignResult

interface ChallengeResponse {
    payload: string    // JWT
    signResult: SignResult
}

// ─── Certificate chain verification ──────────────────────────────────────

/** Verify a certificate chain against the trusted root CA.
 *  Returns the public key (SPKI DER) of the leaf certificate on success. */
function verifyCertChain(certs: string[], rootCA: RootCA): Buffer {
    if (certs.length === 0) throw new Error('Empty certificate chain')

    const x509Certs = certs.map(pem => new crypto.X509Certificate(pem))

    // Verify each certificate is signed by the next one in the chain
    for (let i = 0; i < x509Certs.length - 1; i++) {
        const issuer = x509Certs[i + 1]
        if (!x509Certs[i].verify(issuer.publicKey)) {
            throw new Error(`Certificate #${i} is not signed by certificate #${i + 1}`)
        }
    }

    // Verify the last (closest to root) certificate against the trusted root CA
    const last = x509Certs[x509Certs.length - 1]
    if (!last.verify(rootCA.publicKey)) {
        throw new Error('Root certificate verification failed')
    }

    return x509Certs[0].publicKey.export({ type: 'spki', format: 'der' })
}

// ─── Signature verification ──────────────────────────────────────────────

/** Reconstruct the signed string the client produced. */
function reconstructSignedString(payload: ChallengePayload): string {
    const scopes = Array.from(payload.scopes).sort().join(',')
    return [
        'v2',
        payload.nonce,
        scopes,
    ].join('\n')
}

function verifyWebCryptoSignature(
    signedString: string,
    signatureBase64: string,
    publicKeySpkiDer: Buffer,
): boolean {
    const verify = crypto.createVerify('ed25519')
    verify.update(Buffer.from(signedString, 'utf-8'))
    return verify.verify(
        { key: publicKeySpkiDer, format: 'der', type: 'spki' },
        Buffer.from(signatureBase64, 'base64'),
    )
}

function verifyWebAuthnSignature(
    signedString: string,
    result: WebAuthnSignResult,
    publicKeySpkiDer: Buffer,
): boolean {
    // 1. Compute challenge hash used by client
    const challengeHash = crypto.createHash('sha256').update(Buffer.from(signedString, 'utf-8')).digest()

    // 2. Decode clientDataJSON and verify the challenge field
    const clientDataJSONRaw = Buffer.from(result.clientDataJSON, 'base64')
    let clientData: { challenge: string }
    try {
        clientData = JSON.parse(clientDataJSONRaw.toString('utf-8'))
    } catch {
        return false
    }

    // The challenge in clientDataJSON is base64url-encoded (standard WebAuthn)
    const expectedChallenge = challengeHash.toString('base64url')
    if (clientData.challenge !== expectedChallenge) {
        return false
    }

    // 3. Reconstruct signed data: authenticatorData || SHA-256(clientDataJSON)
    const authData = Buffer.from(result.authenticatorData, 'base64')
    const clientDataHash = crypto.createHash('sha256').update(clientDataJSONRaw).digest()
    const signedData = Buffer.concat([authData, clientDataHash])

    // 4. Verify signature (should be a COSE_Signature1 / Ed25519 or ES256)
    const signature = Buffer.from(result.signature, 'base64')
    const verify = crypto.createVerify('ed25519')
    verify.update(signedData)
    return verify.verify(
        { key: publicKeySpkiDer, format: 'der', type: 'spki' },
        signature,
    )
}

// ─── Main verification ───────────────────────────────────────────────────

type VerificationResult = |
    { ok: true, payload: ChallengePayload, userId?: string } |
    { ok: false, message: string, status: 401 | 400 }

function verifyChallengeResponse(body: ChallengeResponse, rootCA: RootCA): VerificationResult {
    if (typeof body.payload !== 'string') return { ok: false, message: 'Missing or invalid payload', status: 400 }

    const sr = body.signResult
    if (!sr || typeof sr !== 'object') return { ok: false, message: 'Missing or invalid signResult', status: 400 }
    if (sr.type !== 'webcrypto' && sr.type !== 'webauthn') return { ok: false, message: 'Unknown signResult type', status: 400 }
    if (!Array.isArray(sr.certs) || !sr.certs.every(c => typeof c === 'string')) return { ok: false, message: 'Missing or invalid certs', status: 400 }

    // verify payload authenticity
    const challengePayload = verifyChallenge(body.payload)
    if (!challengePayload) return { ok: false, message: 'Unauthorized payload', status: 401 }

    // verify the signed string matches the challenge payload
    const signedString = reconstructSignedString(challengePayload)

    // verify certificate chain and extract leaf public key
    let publicKeySpkiDer: Buffer
    try {
        publicKeySpkiDer = verifyCertChain(sr.certs, rootCA)
    } catch (err: any) {
        return { ok: false, message: `Certificate verification failed: ${err.message}`, status: 401 }
    }

    // verify signature
    let valid: boolean
    if (sr.type === 'webcrypto') {
        if (typeof sr.signature !== 'string') return { ok: false, message: 'Missing webcrypto signature', status: 400 }
        valid = verifyWebCryptoSignature(signedString, sr.signature, publicKeySpkiDer)
    } else {
        // webauthn
        if (typeof sr.credentialId !== 'string') return { ok: false, message: 'Missing credentialId', status: 400 }
        if (typeof sr.clientDataJSON !== 'string') return { ok: false, message: 'Missing clientDataJSON', status: 400 }
        if (typeof sr.authenticatorData !== 'string') return { ok: false, message: 'Missing authenticatorData', status: 400 }
        if (typeof sr.signature !== 'string') return { ok: false, message: 'Missing signature', status: 400 }
        valid = verifyWebAuthnSignature(signedString, sr, publicKeySpkiDer)
    }

    if (!valid) {
        return { ok: false, message: 'Signature verification failed', status: 401 }
    }

    return { ok: true, payload: challengePayload }
}

authRoute.post('/', async (c) => {
    // complete auth challenge, acquire access token
    const body: ChallengeResponse = await c.req.json()
    const response = verifyChallengeResponse(body, rootCA);
    if (!response.ok) {
        return new Response(response.message, { status: response.status })
    }
    const accessToken = newAccessToken({
        scopes: response.payload.scopes,
        userId: response.userId,
    })

    return c.json({ accessToken })
})

export default authRoute