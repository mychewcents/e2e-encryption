/// <reference types="node" />

declare module 'e2e-encryption' {
  class E2E {
    publicKey: string;
    privateKey: string;

    constructor(publicKey: string | undefined, privateKey: string | undefined);
    Encrypt: (plainText: Object, clientPublicKey: string) => string;
    Decrypt: (cipherText: string, publicKey: string) => string;
  }

  export = E2E;
}
