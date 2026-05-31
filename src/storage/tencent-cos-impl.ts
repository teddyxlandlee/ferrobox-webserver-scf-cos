import {AbstractObjectStorage, ObjectStorageCredentials} from "./object-storage.js";
import COS from "cos-nodejs-sdk-v5";

export class TencentCosObjectStorage extends AbstractObjectStorage {
    private acquireObjectUrl(key: string, method: 'PUT' | 'DELETE'): Promise<string> {
        return new Promise((resolve, reject) => {
            this.cos.getObjectUrl({
                Bucket: this.credentials.bucket,
                Region: this.credentials.region,
                Sign: true,
                Key: key,
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

    private cos: COS

    constructor(credentials: ObjectStorageCredentials) {
        super(credentials);
        this.cos = new COS({
            SecretKey: credentials.accessKey,
            SecretId: credentials.accessId,
        })
    }
}
