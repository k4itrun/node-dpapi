# node-dpapi
Node native module to encrypt/decrypt data. On Windows, it uses DPAPI

## API:
```typescript
function unprotectData(
    encryptedData: Uint8Array,
    optionalEntropy: Uint8Array,
    scope: "CurrentUser" | "LocalMachine"
): Uint8Array;
```

## Example:
```javascript
const unprotectData = require("win-dpapi");

const decrypted = unprotectData("*******", null, "CurrentUser");
console.log(`Machine Decrypted: '${decrypted}'`);
```

## FAQ:
Q: Does this work on all platforms?

A: Currently it just works on Windows

## Publish note
This package originates from [k4itrun/node-dpapi](https://github.com/k4itrun/node-dpapi), but he [did not publish it to npm](https://github.com/k4itrun/node-dpapi/issues/1).  [I](https://github.com/k4itrun) have taken the liberty of publishing this package so it may be used as a dependency.