import {AbstractObjectStorage, ObjectStorageCredentials} from "./object-storage.js";
// import COS from "cos-nodejs-sdk-v5";

interface TencentCOS {
    getObjectUrl(
        params: {
            Bucket: string,
            Region: string,
            Sign: boolean,
            Key: string,
            Method: 'PUT' | 'DELETE',
        },
        callback: (err: Error | null, data: { Url: string }) => void
    ): void
}

interface COSConstructor {
    new (options: { SecretId: string, SecretKey: string }): TencentCOS
}

export class TencentCosObjectStorage extends AbstractObjectStorage {
    private acquireObjectUrl(key: string, method: 'PUT' | 'DELETE'): Promise<string> {
        return new Promise((resolve, reject) => {
            this.cos.getObjectUrl({
                Bucket: this.credentials.bucket,
                Region: this.credentials.region,
                Sign: true,
                Key: key,
                //Expires?
                Method: method,
            }, (err, data) => {
                if (err) {
                    reject({type: 'CosError', message: err.message, errorObject: err})
                } else {
                    resolve(data.Url)
                }
            })
        })
    }

    override acquirePutUrl = (key: string) => this.acquireObjectUrl(key, 'PUT')

    override acquireDeleteUrl = (key: string) => this.acquireObjectUrl(key, 'DELETE')

    private readonly cos: TencentCOS

    constructor(credentials: ObjectStorageCredentials) {
        super(credentials);
        const COS: COSConstructor = require('cos-nodejs-sdk-v5')
        this.cos = new COS({
            SecretKey: credentials.accessKey,
            SecretId: credentials.accessId,
        })
    }
}
