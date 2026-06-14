import { AbstractObjectStorage, ObjectStorageCredentials } from "./object-storage.js";
import OSS from 'ali-oss';

const WINDOW_SECONDS = 60

export class AliyunOssObjectStorage extends AbstractObjectStorage {
    private readonly oss: OSS

    constructor(credentials: ObjectStorageCredentials) {
        super(credentials);
        this.oss = new OSS({
            region: credentials.region,
            accessKeyId: credentials.accessId,
            accessKeySecret: credentials.accessKey,
            bucket: credentials.bucket,
            secure: true,
            authorizationV4: true,
        })
    }

    private signUrl(key: string, method: 'PUT' | 'DELETE', contentType?: string): Promise<string> {
        // Note: empty is treated like undefined
        const request = contentType ? {
            headers: { 'content-type': contentType }
        } : {}

        return this.oss.signatureUrlV4(method, WINDOW_SECONDS, request, key, contentType ? ['content-type'] : [])
    }

    acquirePutUrl = (key: string, contentType?: string) => this.signUrl(key, 'PUT', contentType)
    acquireDeleteUrl = (key: string) => this.signUrl(key, 'DELETE')
}