/* eslint-disable new-cap */
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
import { AsnProp, AsnPropTypes } from '@peculiar/asn1-schema';
import { ContentInfo } from '@peculiar/asn1-cms';
import { Certificate } from '@peculiar/asn1-x509';
import { DnssecChainSchema } from './DnssecChainSchema.js';
export class SignatureBundleSchema {
}
__decorate([
    AsnProp({ type: AsnPropTypes.Integer, context: 0, implicit: true })
], SignatureBundleSchema.prototype, "version", void 0);
__decorate([
    AsnProp({ type: DnssecChainSchema, context: 1, implicit: true })
], SignatureBundleSchema.prototype, "dnssecChain", void 0);
__decorate([
    AsnProp({ type: Certificate, context: 2, implicit: true })
], SignatureBundleSchema.prototype, "organisationCertificate", void 0);
__decorate([
    AsnProp({ type: ContentInfo, context: 3, implicit: true })
], SignatureBundleSchema.prototype, "signature", void 0);
//# sourceMappingURL=SignatureBundleSchema.js.map