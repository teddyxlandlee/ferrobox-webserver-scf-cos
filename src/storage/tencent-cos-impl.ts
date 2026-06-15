import {AbstractObjectStorage, ObjectStorageCredentials, WINDOW_SECONDS} from "./object-storage.js";
import crypto, { sign } from 'node:crypto'

// UTF-8 string -> hex string
function hmacSha1(secret: string, message: string): string {
    return crypto.createHmac('sha1', Buffer.from(secret, 'utf-8')).update(message).digest('hex')
}

// UTF-8 string -> hex string
function sha1(message: string): string {
    return crypto.createHash('sha1').update(message).digest('hex')
}

// -> map, list
function canonicalizeRecord(record: Record<string, string>): [string, string] {
    const params = new URLSearchParams()
    const keys: string[] = []
    for (const [k, v] of Object.entries(record)) {
        const lowerKey = k.toLowerCase()
        keys.push(encodeURIComponent(lowerKey))
        params.append(lowerKey, v)
    }

    return [params.toString(), keys.join(';')]
}

export class TencentCosObjectStorage extends AbstractObjectStorage {
    private acquireObjectUrl(key: string, method: 'PUT' | 'DELETE' | 'GET', headers?: Record<string, string>): Promise<string> {
        /*
        URLSearchParams {
            'q-sign-algorithm' => 'sha1',
            'q-ak' => 'SECRET_ID',
            'q-sign-time' => '1781524344;1781524404',
            'q-key-time' => '1781524344;1781524404',
            'q-header-list' => 'host',
            'q-url-param-list' => '',
            'q-signature' => '2809fef701f3834fbcafc27e97121049db749a89'
        }
        */

        if (!headers) headers = {}
        headers.host = `${this.credentials.bucket}.cos.${this.credentials.region}.myqcloud.com`
        const url = new URL('/' + key, 'https://' + headers.host)

        const currentTime = Math.floor(Date.now() / 1000)
        const expireTime = currentTime + WINDOW_SECONDS
        const keyTime: string = currentTime + ';' + expireTime
        const [queryMap, queryList] = canonicalizeRecord({/* empty */})
        const [headerMap, headerList] = canonicalizeRecord(headers)
        
        const signKey = hmacSha1(this.credentials.accessKey, keyTime)
        const httpString = [
            method.toLowerCase(),
            '/' + key,
            queryMap,
            headerMap,
        ].join('\n') + '\n'
        const stringToSign = [
            'sha1',
            keyTime,
            sha1(httpString)
        ].join('\n') + '\n'
        const signature = hmacSha1(signKey, stringToSign)

        const appendedQueries: Record<string, string> = {
            'q-sign-algorithm': 'sha1',
            'q-ak': this.credentials.accessId,
            'q-sign-time': keyTime,
            'q-key-time': keyTime,
            'q-header-list': headerList,
            'q-url-param-list': queryList,
            'q-signature': signature,
        }
        for (const [k, v] of Object.entries(appendedQueries)) {
            url.searchParams.append(k, v)
        }

        return Promise.resolve(url.href)
    }

    override acquirePutUrl(key: string, contentType?: string) {
        const headers: Record<string, string> = contentType ? {'Content-Type': contentType} : {}
        return this.acquireObjectUrl(key, 'PUT', headers)
    }

    override acquireDeleteUrl = (key: string) => this.acquireObjectUrl(key, 'DELETE')

    constructor(credentials: ObjectStorageCredentials) {
        super(credentials);
    }

    acquireGetUrl = (key: string) => this.acquireObjectUrl(key, 'GET')
}
