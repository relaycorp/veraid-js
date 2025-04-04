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
import { MemberIdBundle, SignatureBundle } from '@relaycorp/veraid';
import { addDays } from 'date-fns';

const TTL_DAYS = 30;
const SERVICE_OID = '1.2.3.4.5';

async function produceSignature(
  plaintext: ArrayBuffer,
  memberIdBundleSerialised: ArrayBuffer,
  memberSigningKey: CryptoKey,
): Promise<ArrayBuffer> {
  const memberIdBundle = MemberIdBundle.deserialise(memberIdBundleSerialised);
  const expiryDate = addDays(new Date(), TTL_DAYS);
  const signatureBundle = await SignatureBundle.sign(
    plaintext,
    SERVICE_OID,
    memberIdBundle,
    memberSigningKey,
    expiryDate,
  );
  return signatureBundle.serialise();
}
```

The output is the _VeraId Signature Bundle_, which contains the Member Id Bundle and the actual signature. It does not include the plaintext.

To produce an _organisation signature_, use the class [`OrganisationSigner`](https://docs.relaycorp.tech/veraid-js/classes/OrganisationSigner.html) instead of a `MemberIdBundle`.

Note that for signatures to actually be valid for up to 30 days, the TTL override in the VeraId TXT record should allow 30 days or more.

### Signature verification

To verify a VeraId signature, you simply need the Signature Bundle and the plaintext to be verified. For extra security, this library also requires you to confirm the service where you intend to use the plaintext.

If VeraId's maximum TTL of 90 days or the TTL specified by the signature producer may be too large for your application, you may also want to restrict the validity period of signatures.

For example, if you only want to accept signatures valid for the past 30 days in a service identified by `1.2.3.4.5`, you could use the following function:

```typescript
import { type IDatePeriod, SignatureBundle } from '@relaycorp/veraid';
import { subDays } from 'date-fns';

const TTL_DAYS = 30;
const SERVICE_OID = '1.2.3.4.5';

async function verifySignature(
  plaintext: ArrayBuffer,
  signatureBundleSerialised: ArrayBuffer,
): Promise<string> {
  const now = new Date();
  const datePeriod: IDatePeriod = { start: subDays(now, TTL_DAYS), end: now };
  const signatureBundle = SignatureBundle.deserialise(signatureBundleSerialised);
  const {
    member: { user, organisation },
  } = await signatureBundle.verify(plaintext, SERVICE_OID, datePeriod);
  return user === undefined ? organisation : `${user}@${organisation}`;
}
```

`signatureBundle.verify()` will throw an error if the signature is invalid for whatever reason.
See [`SignatureBundleVerification`](https://docs.relaycorp.tech/veraid-js/interfaces/SignatureBundleVerification.html) for more details on the result.

`verifySignature()` will return the id of the VeraId member that signed the plaintext, which looks like `user@example.com` if the member is a user or simply `example.com` if the member is a bot (acting on behalf of the organisation `example.com`).

### Testing with mock trust chains

You can use the [`MockTrustChain`](https://docs.relaycorp.tech/veraid-js/interfaces/MockTrustChainOptions.html) class to test your integration with VeraId by generating valid signature bundles without the real DNSSEC infrastructure. This makes it easy to test both signature creation and verification in your automated tests, but it won't work in production because it relies on mock DNSSEC trust anchors.

For example, to test the `produceSignature()` function illustrated above, you could use `MockTrustChain` as follows:

```typescript
import { MockTrustChain } from '@relaycorp/veraid';
import { addMinutes } from 'date-fns';
import { describe, expect, test } from 'vitest';

const mockTrustChain = await MockTrustChain.generate(
  'example.com', 
  'alice', // Use `undefined` for bot signatures
  addMinutes(new Date(), 10), // Expiry date
);

describe('produceSignature', () => {
  test('should produce valid signatures', async () => {
    const plaintext = new TextEncoder().encode('Hello world');
    const memberIdBundleSerialised = mockTrustChain.chain.serialise();

    const signatureBundleSerialised = await produceSignature(
      plaintext,
      memberIdBundleSerialised,
      mockTrustChain.signerPrivateKey,
    );

    const signatureBundle = SignatureBundle.deserialise(signatureBundleSerialised);
    const { member } = await signatureBundle.verify(
      undefined, // The plaintext is already encapsulated
      SERVICE_OID,
      new Date(),
      mockTrustChain.dnssecTrustAnchors,
    );
    expect(member.organisation).toBe('example.com');
    expect(member.user).toBe('alice');
  });
});
```

To test the `verifySignature()` function illustrated above, you'd have to add an optional parameter for the DNSSEC trust anchors and use `MockTrustChain` as follows:

```typescript
import { type IDatePeriod, type TrustAnchor, MockTrustChain, SignatureBundle } from '@relaycorp/veraid';
import { addMinutes, subDays } from 'date-fns';
import { describe, expect, test } from 'vitest';

// Modify the verifySignature function to accept custom trust anchors
async function verifySignature(
  plaintext: ArrayBuffer,
  signatureBundleSerialised: ArrayBuffer,
  customTrustAnchors?: readonly TrustAnchor[], // New optional parameter
): Promise<string> {
  const now = new Date();
  const datePeriod: IDatePeriod = { start: subDays(now, TTL_DAYS), end: now };
  const signatureBundle = SignatureBundle.deserialise(signatureBundleSerialised);
  const {
    member: { user, organisation },
  } = await signatureBundle.verify(plaintext, SERVICE_OID, datePeriod, customTrustAnchors);
  return user === undefined ? organisation : `${user}@${organisation}`;
}

const mockTrustChain = await MockTrustChain.generate(
  'example.com', 
  'alice', 
  addMinutes(new Date(), 10), // Expiry date
);

describe('verifySignature', () => {
  test('should verify valid signatures', async () => {
    const plaintext = new TextEncoder().encode('Hello world');
    const signatureBundle = await mockTrustChain.sign(plaintext, SERVICE_OID);

    const memberId = await verifySignature(
      plaintext,
      signatureBundle.serialise(),
      mockTrustChain.dnssecTrustAnchors, // Important: Pass the mock trust anchors
    );

    expect(memberId).toBe('alice@example.com');
  });
});
```

## API docs

The API documentation can be found on [docs.relaycorp.tech](https://docs.relaycorp.tech/veraid-js/).

## WebCrypto notes

Private keys passed to this library may optionally define a `provider` property, which would be used as the `SubtleCrypto` instance when producing digital signatures (e.g., when issuing certificates). If not provided, the default `SubtleCrypto` instance will be used.

As of this writing, only [`@relaycorp/webcrypto-kms`](https://www.npmjs.com/package/@relaycorp/webcrypto-kms) supports this functionality.

## Contributions

We love contributions! If you haven't contributed to a Relaycorp project before, please take a minute to [read our guidelines](https://github.com/relaycorp/.github/blob/master/CONTRIBUTING.md) first.
