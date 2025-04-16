import { VeraidError } from '../../VeraidError.js';
export default class CertificateError extends VeraidError {
    constructor() {
        super(...arguments);
        this.name = 'CertificateError';
    }
}
//# sourceMappingURL=CertificateError.js.map