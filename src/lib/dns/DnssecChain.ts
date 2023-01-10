import { AsnArray, AsnPropTypes, AsnType, AsnTypeTypes } from '@peculiar/asn1-schema';

// eslint-disable-next-line new-cap
@AsnType({ type: AsnTypeTypes.Set, itemType: AsnPropTypes.OctetString })
export class DnssecChain extends AsnArray<ArrayBuffer> {}
