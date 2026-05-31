import {Hono} from "hono";
import {CONTEXT_TOKEN_IDENTITY, EnvWithTokenIdentity, verifier} from "./access-token.js";
import {ObjectStorage} from "./storage/object-storage.js";
import {TencentCosObjectStorage} from "./storage/tencent-cos-impl.js";
import {dataCosCredentials, metaCosCredentials} from "./cos-credentials.js";

const uploadRoute = new Hono<EnvWithTokenIdentity & {
    Variables: {
        slug: string,
    }
}>({
    strict: false
})

uploadRoute.post('*', verifier, async (c, next) => {
    const tokenIdentity = c.get(CONTEXT_TOKEN_IDENTITY)
    if (!tokenIdentity.scopes.includes('upload')) return c.text('Forbidden', 403)
    const body = await c.req.json()
    if (!body || typeof body !== 'object' || typeof body.slug !== 'string') return c.text('Bad request', 400)
    c.set("slug", body.slug)
    return next()
})

// Respond a JSON that contains "url" (pre-signed)

uploadRoute.post('/meta', async (c) => {
    if (!metaCosCredentials) return c.text('Meta storage not supported', 500)

    const slug = c.get("slug")
    const objectStorage: ObjectStorage = new TencentCosObjectStorage(metaCosCredentials)
    const url = await objectStorage.acquirePutUrl(`${slug}.json`)
    return c.json({url})
})

uploadRoute.post('/data', async (c) => {
    if (!dataCosCredentials) return c.text('Data storage not supported', 500)

    const slug = c.get("slug")
    const objectStorage: ObjectStorage = new TencentCosObjectStorage(dataCosCredentials)
    const url = await objectStorage.acquirePutUrl(`${slug}.json`)
    return c.json({url})
})

export default uploadRoute