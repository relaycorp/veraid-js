export function expectErrorToEqual(error, expectedError) {
    expect(typeof error).toEqual(typeof expectedError);
    expect(error.name).toEqual(expectedError.name);
    expect(error.message).toEqual(expectedError.message);
    expect(error.cause).toEqual(expectedError.cause);
}
export function expectFunctionToThrowError(erroneousFunction, expectedError) {
    let error;
    try {
        erroneousFunction();
    }
    catch (err) {
        error = err;
    }
    expectErrorToEqual(error, expectedError);
}
export async function getPromiseRejection(rejectingFunction, expectedErrorType) {
    let error;
    try {
        await rejectingFunction();
    }
    catch (err) {
        error = err;
    }
    expect(error).toBeInstanceOf(expectedErrorType);
    return error;
}
//# sourceMappingURL=errors.js.map