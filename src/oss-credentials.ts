import {ObjectStorageCredentials} from "./storage/object-storage.js";

const {
    OSS_META_BUCKET,
    OSS_META_REGION,
    OSS_META_ACCESS_ID,
    OSS_META_ACCESS_KEY,

    OSS_DATA_BUCKET,
    OSS_DATA_REGION,
    OSS_DATA_ACCESS_ID,
    OSS_DATA_ACCESS_KEY,
} = process.env

export const metaOssCredentials: ObjectStorageCredentials | null =
    OSS_META_BUCKET && OSS_META_REGION && OSS_META_ACCESS_ID && OSS_META_ACCESS_KEY ? {
        bucket: OSS_META_BUCKET,
        region: OSS_META_REGION,
        accessId: OSS_META_ACCESS_ID,
        accessKey: OSS_META_ACCESS_KEY,
    } : null
export const dataOssCredentials: ObjectStorageCredentials | null =
    OSS_DATA_BUCKET && OSS_DATA_REGION && OSS_DATA_ACCESS_ID && OSS_DATA_ACCESS_KEY ? {
        bucket: OSS_DATA_BUCKET,
        region: OSS_DATA_REGION,
        accessId: OSS_DATA_ACCESS_ID,
        accessKey: OSS_DATA_ACCESS_KEY,
    } : null