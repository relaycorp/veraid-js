import { MockRsaPssProvider } from '../../../testUtils/webcrypto/MockRsaPssProvider.js';
import { PrivateKey } from './PrivateKey.js';
const PROVIDER = new MockRsaPssProvider();
const ALGORITHM = { name: 'RSA-PSS' };
describe('PrivateKey', () => {
    class StubPrivateKey extends PrivateKey {
        constructor(algorithm, provider) {
            super(algorithm, provider);
        }
    }
    test('Key type should be private', () => {
        const key = new StubPrivateKey(ALGORITHM, PROVIDER);
        expect(key.type).toBe('private');
    });
    test('Key should be extractable', () => {
        const key = new StubPrivateKey(ALGORITHM, PROVIDER);
        expect(key.extractable).toBeTrue();
    });
    test('Algorithm should be honoured', () => {
        const key = new StubPrivateKey(ALGORITHM, PROVIDER);
        expect(key.algorithm).toStrictEqual(ALGORITHM);
    });
    test('Provider should be honoured', () => {
        const key = new StubPrivateKey(ALGORITHM, PROVIDER);
        expect(key.provider).toStrictEqual(PROVIDER);
    });
});
//# sourceMappingURL=PrivateKey.spec.js.map