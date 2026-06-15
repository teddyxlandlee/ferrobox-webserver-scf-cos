import {Hono} from "hono";
import {CONTEXT_TOKEN_IDENTITY, EnvWithTokenIdentity, verifier} from "./access-token.js";
import {ObjectStorage} from "./storage/object-storage.js";
import {AliyunOssObjectStorage} from "./storage/aliyun-oss-impl.js";
import {dataOssCredentials, metaOssCredentials} from "./oss-credentials.js";

const deleteRoute = new Hono<EnvWithTokenIdentity & {
    Variables: {
        slug: string,
    }
}>({
    strict: false
})

deleteRoute.post('*', verifier, async (c, next) => {
    const tokenIdentity = c.get(CONTEXT_TOKEN_IDENTITY)
    if (!tokenIdentity.scopes.includes('delete')) return c.text('Forbidden', 403)
    const body = await c.req.json()
    if (!body || typeof body !== 'object' || typeof body.slug !== 'string') return c.text('Bad request', 400)
    c.set("slug", body.slug)
    return next()
})

// Respond a JSON that contains "url" (pre-signed)

deleteRoute.post('/meta', async (c) => {
    if (!metaOssCredentials) return c.text('Meta storage not supported', 500)

    const slug = c.get("slug")
    const objectStorage: ObjectStorage = new AliyunOssObjectStorage(metaOssCredentials)
    const url = await objectStorage.acquireDeleteUrl(`${slug}.json`)
    return c.json({url})
})

deleteRoute.post('/data', async (c) => {
    if (!dataOssCredentials) return c.text('Data storage not supported', 500)

    const slug = c.get("slug")
    const objectStorage: ObjectStorage = new AliyunOssObjectStorage(dataOssCredentials)
    const url = await objectStorage.acquireDeleteUrl(`${slug}.bin`)
    return c.json({url})
})

export default deleteRoute