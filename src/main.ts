import { Hono } from 'hono'
import { serve } from "@hono/node-server"

import authRoute from './route-auth.js'
import uploadRoute from "./route-upload.js";
import deleteRoute from "./route-delete.js";

const app = new Hono({
    strict: false
})

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