function expectErrorToEqual(error: Error | undefined, expectedError: Error) {
  expect(error).toBeInstanceOf(Error);
  expect(error!.name).toEqual(expectedError.name);
  expect(error!.name).toEqual(expectedError.name);
  expect(error!.message).toEqual(expectedError.message);
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

  expectErrorToEqual(error, expectedError);
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

  expectErrorToEqual(error, expectedError);
}
