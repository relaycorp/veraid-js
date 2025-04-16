export declare function expectErrorToEqual<ErrorType extends Error>(error: ErrorType, expectedError: ErrorType): void;
export declare function expectFunctionToThrowError(erroneousFunction: () => unknown, expectedError: Error): void;
export declare function getPromiseRejection<ErrorType extends Error>(rejectingFunction: () => Promise<unknown>, expectedErrorType: new () => ErrorType): Promise<ErrorType>;
