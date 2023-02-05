# VeraId library for Node.js

[![npm version](https://badge.fury.io/js/@relaycorp%2Fveraid.svg)](https://www.npmjs.com/package/@relaycorp/veraid)

This is the Node.js implementation of [Vera](https://vera.domains), an offline authentication protocol powered by DNSSEC. It implements all the building blocks that signature producers and consumers need.

The latest version can be installed from NPM:

```shell
npm install @relaycorp/veraid
```

## Usage

### Producing signatures

To produce a signature for a given plaintext, you need a _Vera Member Id Bundle_ (produced by a Vera CA Server; not yet implemented as of this writing) and the Vera Member's private key.

For example, if you wanted to produce signatures valid for up to 30 days for a service identified by the [OID](https://en.wikipedia.org/wiki/Object_identifier) `1.2.3.4.5`, you could implement the following function and call it in your code:

```typescript
import { sign } from '@relaycorp/veraid';
import { addDays } from 'date-fns';

const TTL_DAYS = 30;
const SERVICE_OID = '1.2.3.4.5';

async function produceSignature(
  plaintext: ArrayBuffer,
  memberIdBundleSerialised: ArrayBuffer,
  signingKey: CryptoKey,
): Promise<ArrayBuffer> {
  const expiryDate = addDays(new Date(), TTL_DAYS);
  return await sign(
    plaintext,
    SERVICE_OID,
    memberIdBundleSerialised,
    signingKey,
    expiryDate,
  );
}
```

### Signature verification

## Node.js version support

This library requires Node.js v16.9 or newer, but going forward we will follow the Node.js release schedule.

## Contributions

We love contributions! If you haven't contributed to a Relaycorp project before, please take a minute to [read our guidelines](https://github.com/relaycorp/.github/blob/master/CONTRIBUTING.md) first.
