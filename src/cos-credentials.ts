import {ObjectStorageCredentials} from "./storage/object-storage.js";

const {
    COS_META_BUCKET,
    COS_META_REGION,
    COS_META_ACCESS_ID,
    COS_META_ACCESS_KEY,

    COS_DATA_BUCKET,
    COS_DATA_REGION,
    COS_DATA_ACCESS_ID,
    COS_DATA_ACCESS_KEY,
} = process.env

export const metaCosCredentials: ObjectStorageCredentials | null =
    COS_META_BUCKET && COS_META_REGION && COS_META_ACCESS_ID && COS_META_ACCESS_KEY ? {
        bucket: COS_META_BUCKET,
        region: COS_META_REGION,
        accessId: COS_META_ACCESS_ID,
        accessKey: COS_META_ACCESS_KEY,
    } : null
export const dataCosCredentials: ObjectStorageCredentials | null =
    COS_DATA_BUCKET && COS_DATA_REGION && COS_DATA_ACCESS_ID && COS_DATA_ACCESS_KEY ? {
        bucket: COS_DATA_BUCKET,
        region: COS_DATA_REGION,
        accessId: COS_DATA_ACCESS_ID,
        accessKey: COS_DATA_ACCESS_KEY,
    } : null