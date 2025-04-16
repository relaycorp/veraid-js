export function asn1Serialise(asn1Value) {
    return Buffer.from(asn1Value.toBER());
}
export function expectAsn1ValuesToBeEqual(expectedValue, actualValue) {
    expect(Buffer.from(actualValue.toBER(false))).toEqual(Buffer.from(expectedValue.toBER(false)));
}
//# sourceMappingURL=asn1.js.map