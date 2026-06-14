import {Buffer} from "node:buffer";
import * as jwt from 'jsonwebtoken'
import {assert} from "./assert.js";
import {MiddlewareHandler} from 'hono'

// NOTE: distinguish with JWT_AUTH_CHALLENGE
const JWT_ACCESS_TOKEN = Buffer.from(process.env.JWT_ACCESS_TOKEN || '', 'base64')
assert(JWT_ACCESS_TOKEN.length > 0, 'JWT_ACCESS_TOKEN is empty')

const SCOPES = [
    'upload', 'delete'
] as const
export type Scope = typeof SCOPES[number]
const EXPIRE_IN = '5min'

type RealPayload = {
    scopes: Scope[]
}

export type TokenIdentity = {
    scopes: Scope[],
    userId?: string,
}

export function newAccessToken(payload: TokenIdentity): string {
    const realPayload: RealPayload = {
        scopes: Array.from(payload.scopes).sort()
    }
    const signOptions: jwt.SignOptions = {
        expiresIn: EXPIRE_IN,
        keyid: 'access'
    }
    if (typeof payload.userId === 'string') {
        signOptions.subject = payload.userId
    }
    return jwt.sign(realPayload, JWT_ACCESS_TOKEN, signOptions)
}

export function verifyAccessToken(token: string): null | TokenIdentity {
    try {
        const payload = jwt.verify(token, JWT_ACCESS_TOKEN) as string | (RealPayload & jwt.JwtPayload)
        console.log('[PAYLOAD]', JSON.stringify(payload))
        if (typeof payload === 'string') return null    // invalid
        const scopes = payload.scopes
        if (!Array.isArray(scopes) || !scopes.every(SCOPES.includes)) return null    // invalid scope
        return {
            scopes,
            userId: payload.sub,
        }
    } catch {
        return null
    }
}

export function getAllScopes(): Scope[] {
    return Array.from(SCOPES)
}

export const CONTEXT_TOKEN_IDENTITY = 'token-identity'
export type EnvWithTokenIdentity = {
    Variables: {
        [CONTEXT_TOKEN_IDENTITY]: TokenIdentity,
    },
}

export const verifier: MiddlewareHandler = async (c, next) => {
    const auth = c.req.header('Authorization')
    if (!auth) return c.text('Unauthorized', 401)
    const [prefix, token, trash] = auth.split(' ', 3)
    if (prefix !== 'Bearer' || trash) return c.text('Bad token format', 400)

    const payload = verifyAccessToken(token)
    if (!payload) return c.text('Invalid token', 401)

    c.set(CONTEXT_TOKEN_IDENTITY, payload)
    return next()
}
