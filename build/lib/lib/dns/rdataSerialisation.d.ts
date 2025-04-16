import type { VeraidRdataFields } from './VeraidRdataFields.js';
export declare function generateTxtRdata(orgPublicKey: CryptoKey, ttlOverride: number, serviceOid?: string): Promise<string>;
export declare function parseTxtRdata(rdata: Buffer | string | readonly Buffer[]): VeraidRdataFields;
