/**
 * Error while processing CMS value.
 */
export default class CmsError extends Error {
    constructor() {
        super(...arguments);
        this.name = 'CmsError';
    }
}
//# sourceMappingURL=CmsError.js.map