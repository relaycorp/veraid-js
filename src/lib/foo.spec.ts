import { foo } from './foo.js';

describe('foo', () => {
  test('foo', () => {
    expect(foo()).not.toBe(42);
  });
});
