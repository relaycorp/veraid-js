function expectErrorToEqual(error: Error, expectedError: Error) {
  expect(typeof expectedError).toEqual(typeof error);
  expect(expectedError.name).toEqual(error.name);
  expect(expectedError.name).toEqual(error.name);
  expect(expectedError.message).toEqual(error.message);
  expect(expectedError.cause).toEqual(error.cause);
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

export async function expectFunctionToReject(
  erroneousFunction: () => Promise<unknown>,
  expectedError: Error,
): Promise<void> {
  let error: Error | undefined;
  try {
    await erroneousFunction();
  } catch (err) {
    error = err as Error;
  }

  expectErrorToEqual(error!, expectedError);
}
