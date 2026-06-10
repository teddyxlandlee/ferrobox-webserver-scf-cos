import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { serve } from "@hono/node-server"

import authRoute from './route-auth.js'
import uploadRoute from "./route-upload.js";
import deleteRoute from "./route-delete.js";

const app = new Hono({
    strict: false
})

const corsAllowList: readonly string[] = (process.env.CORS_ALLOW_LIST || '')
    .split(',')
    .map(s => s.trim())
    .filter(s => s.length > 0)

// CORS
app.use(cors({
    origin: async (origin, _context) => {
        if (!origin.startsWith('https://')) return null
        const originUrlHostname = new URL(origin).hostname
        for (const allowedOrigin of corsAllowList) {
            if (originUrlHostname === allowedOrigin) return origin
            if (allowedOrigin.startsWith('*.')) {
                const allowedOriginRootDomain = allowedOrigin.substring(1)
                if (originUrlHostname.endsWith(allowedOriginRootDomain)) return origin
            }
        }
        return null
    }
}))

// Auth
app.route('/v2/auth', authRoute)

// Upload
app.route('/v2/upload', uploadRoute)

// Delete
app.route('/v2/delete', deleteRoute)


serve({
    fetch: app.fetch,
    port: parseInt(process.env.PORT || '') || 9000
})