import { jest } from '@jest/globals';
import { RsaPssProvider } from 'webcrypto-core';
export class MockRsaPssProvider extends RsaPssProvider {
    constructor() {
        super(...arguments);
        this.onGenerateKey = jest.fn();
        this.onSign = jest.fn();
        this.onVerify = jest.fn();
        this.onExportKey = jest.fn();
        this.onImportKey = jest.fn();
    }
}
//# sourceMappingURL=MockRsaPssProvider.js.map