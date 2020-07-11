import Encrypt from '../src';

describe('Test', () => {
  it('should simply return the text', () => {
    expect(Encrypt('SHA256', 'Demo Text')).toBe('Demo Text');
  });
});
