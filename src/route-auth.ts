import {Hono} from "hono";
import {getAllScopes, newAccessToken, Scope} from "./access-token.js";
import {uuidv7} from "uuidv7-js";
import {assert} from "./assert.js";
import * as jwt from 'jsonwebtoken'

const authRoute = new Hono({
    strict: false
})

interface ChallengePayload {
    scopes: Scope[],
    nonce: ReturnType<typeof uuidv7>,
}

const TTL = '60s'

const JWT_AUTH_CHALLENGE = Buffer.from(process.env.JWT_AUTH_CHALLENGE || '', 'base64')
assert(!!JWT_AUTH_CHALLENGE, 'JWT_AUTH_CHALLENGE is empty')

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

interface ChallengeResponse {
    payload: string     // JWT
    signature: string
    certs: string[]
}

type RootCA = any
declare const rootCA: RootCA

type VerificationResult = |
    { ok: true, payload: ChallengePayload, userId?: string } |
    { ok: false, message: string, status: 401 | 400 }

function verifyChallengeResponse(body: ChallengeResponse, rootCA: RootCA): VerificationResult {
    if (typeof body.payload !== 'string') return { ok: false, message: 'Missing or invalid payload', status: 400 }
    if (typeof body.signature !== 'string') return { ok: false, message: 'Missing or invalid signature ', status: 400}
    if (!Array.isArray(body.certs) || !body.certs.every((k) => typeof k === 'string')) return { ok: false, message: 'Missing or invalid certs ', status: 400}

    // verify payload authenticity
    const payload = verifyChallenge(body.payload)
    if (!payload) return { ok: false, message: 'Unauthorized payload', status: 401}

    // TODO: verify response with signature & certs
    
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