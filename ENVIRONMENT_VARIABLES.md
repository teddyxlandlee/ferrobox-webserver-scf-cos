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

## `COS_{META,DATA}_{BUCKET,REGION,ACCESS_ID,ACCESS_KEY}`
- Tencent COS entrypoints & credentials
- Format: plaintext

## `PORT`
- Port listened by this process
- Format: number
- Default: 9000

