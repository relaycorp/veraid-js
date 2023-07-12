# VeraId library for Node.js

[![npm version](https://badge.fury.io/js/@relaycorp%2Fveraid.svg)](https://www.npmjs.com/package/@relaycorp/veraid)

This is the Node.js implementation of [VeraId](https://veraid.net), an offline authentication protocol powered by DNSSEC. This library implements all the building blocks that signature producers and consumers need.

The latest version can be installed from NPM:

```shell
npm install @relaycorp/veraid
```

## Usage

### Signature production

To produce a signature for a given plaintext, you need a _Member Id Bundle_ (produced by a VeraId organisation; e.g., via [VeraId Authority](https://github.com/relaycorp/veraid-authority)) and the Member's private key.

For example, if you wanted to produce signatures valid for up to 30 days for a service identified by the [OID](https://en.wikipedia.org/wiki/Object_identifier) `1.2.3.4.5`, you could implement the following function and call it in your code:

```typescript
import { sign } from '@relaycorp/veraid';
import { addDays } from 'date-fns';

const TTL_DAYS = 30;
const SERVICE_OID = '1.2.3.4.5';

async function produceSignature(
  plaintext: ArrayBuffer,
  memberIdBundle: ArrayBuffer,
  memberSigningKey: CryptoKey,
): Promise<ArrayBuffer> {
  const expiryDate = addDays(new Date(), TTL_DAYS);
  return await sign(
    plaintext,
    SERVICE_OID,
    memberIdBundle,
    memberSigningKey,
    expiryDate,
  );
}
```

The output of the `sign()` function is the _Vera Signature Bundle_, which contains the Member Id Bundle and the actual signature. It does not include the plaintext.

Note that for signatures to actually be valid for up to 30 days, the TTL override in the VeraId TXT record should allow 30 days or more.

### Signature verification

To verify a VeraId signature, you simply need the Signature Bundle and the plaintext to be verified. For extra security, this library also requires you to confirm the service where you intend to use the plaintext.

If VeraId's maximum TTL of 90 days or the TTL specified by the signature producer may be too large for your application, you may also want to restrict the validity period of signatures.

For example, if you only want to accept signatures valid for the past 30 days in a service identified by `1.2.3.4.5`, you could use the following function:

```typescript
import { type IDatePeriod, verify } from '@relaycorp/veraid';
import { subDays } from 'date-fns';

const TTL_DAYS = 30;
const SERVICE_OID = '1.2.3.4.5';

async function verifySignature(
  plaintext: ArrayBuffer,
  signatureBundle: ArrayBuffer,
): Promise<string> {
  const now = new Date();
  const datePeriod: IDatePeriod = { start: subDays(now, TTL_DAYS), end: now };
  const { organisation, user } = await verify(
    plaintext,
    signatureBundle,
    SERVICE_OID,
    datePeriod,
  );
  return user === undefined ? organisation : `${user}@${organisation}`;
}
```

`verify()` will throw an error if the signature is invalid for whatever reason.

`verifySignature()` will return the id of the VeraId member that signed the plaintext, which looks like `user@example.com` if the member is a user or simply `example.com` if the member is a bot (acting on behalf of the organisation `example.com`).

## API docs

The API documentation can be found on [docs.relaycorp.tech](https://docs.relaycorp.tech/veraid-js/).

## WebCrypto notes

Private keys passed to this library may optionally define a `provider` property, which would be used as the `SubtleCrypto` instance when producing digital signatures (e.g., when issuing certificates). If not provided, the default `SubtleCrypto` instance will be used.

As of this writing, only [`@relaycorp/webcrypto-kms`](https://www.npmjs.com/package/@relaycorp/webcrypto-kms) supports this functionality.

## Contributions

We love contributions! If you haven't contributed to a Relaycorp project before, please take a minute to [read our guidelines](https://github.com/relaycorp/.github/blob/master/CONTRIBUTING.md) first.
