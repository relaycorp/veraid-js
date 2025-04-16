/* eslint-disable new-cap */
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
import { AsnProp, AsnPropTypes } from '@peculiar/asn1-schema';
import { DatePeriodSchema } from './DatePeriodSchema.js';
export class SignatureMetadataSchema {
}
__decorate([
    AsnProp({ type: AsnPropTypes.ObjectIdentifier, context: 0, implicit: true })
], SignatureMetadataSchema.prototype, "serviceOid", void 0);
__decorate([
    AsnProp({ type: DatePeriodSchema, context: 1, implicit: true })
], SignatureMetadataSchema.prototype, "validityPeriod", void 0);
//# sourceMappingURL=SignatureMetadataSchema.js.map