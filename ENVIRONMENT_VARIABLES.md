# Environment Variables

## `JWT_ACCESS_TOKEN`
- Used to sign access tokens
- Format: base64

## `JWT_AUTH_CHALLENGE`
- Used to sign authentication challenge payload
- Format: base64

## `ROOT_CA_PEM`
- Root certificate
- Format: PEM

## `OSS_{META,DATA}_{BUCKET,REGION,ACCESS_ID,ACCESS_KEY}`
- Aliyun OSS entrypoints & credentials
- Format: plaintext

## `PORT`
- Port listened by this process
- Format: number
- Default: 9000

## `CORS_ALLOW_LIST`
- Allowed origins (hostnames) of CORS requests. Only HTTPS requests are accepted.
- Format: plaintext, separated by comma (`,`)
- Example: `example.org,*.example.com`

