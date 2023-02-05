export function expectErrorToEqual<ErrorType extends Error>(
  error: ErrorType,
  expectedError: ErrorType,
) {
  expect(typeof error).toEqual(typeof expectedError);
  expect(error.name).toEqual(expectedError.name);
  expect(error.message).toEqual(expectedError.message);
  expect(error.cause).toEqual(expectedError.cause);
}

export function expectFunctionToThrowError(
  erroneousFunction: () => unknown,
  expectedError: Error,
): void {
  let error: Error | undefined;
  try {
    erroneousFunction();
  } catch (err) {
    error = err as Error;
  }

  expectErrorToEqual(error!, expectedError);
}

export async function getPromiseRejection<ErrorType extends Error>(
  rejectingFunction: () => Promise<unknown>,
  expectedErrorType: new () => ErrorType,
): Promise<ErrorType> {
  let error: ErrorType | undefined;
  try {
    await rejectingFunction();
  } catch (err) {
    error = err as ErrorType;
  }

  expect(error).toBeInstanceOf(expectedErrorType);
  return error!;
}
