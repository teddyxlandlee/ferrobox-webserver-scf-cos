export interface ObjectStorage {
    acquirePutUrl(key: string, contentType?: string): Promise<string>
    acquireDeleteUrl(key: string): Promise<string>
}

export interface ObjectStorageCredentials {
    accessId: string
    accessKey: string
    bucket: string
    region: string
}

export abstract class AbstractObjectStorage<
    C extends ObjectStorageCredentials = ObjectStorageCredentials,
> implements ObjectStorage {
    abstract acquirePutUrl(key: string, contentType?: string): Promise<string>
    abstract acquireDeleteUrl(key: string): Promise<string>

    protected constructor(protected credentials: C) {}
}
