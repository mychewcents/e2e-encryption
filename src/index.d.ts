/// <reference types="node" />

declare module 'e2e-encryption' {
  type Options = {
    useSameKeyPerClient: boolean;
  };

  type SymmetricKeyObject = {
    raw: string;
    enc: string;
  };

  type SymmetricKeyEntryMap = {
    [publicKey: string]: SymmetricKeyObject;
  };

  class E2E {
    publicKey: string;
    privateKey: string;
    readonly SymmetricKeys: SymmetricKeyEntryMap;
    readonly options: Options;

    constructor(publicKey: string, privateKey: string, options: Options);

    Encrypt: (
      plainText: Object,
      clientPublicKey: string,
      options: Options,
    ) => string;

    Decrypt: (
      cipherText: string,
      publicKey: string,
      options: Options,
    ) => Object;
  }

  export = E2E;
}
