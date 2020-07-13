# e2e-encryption (End-to-End Encryption `npm` Package)

![Travis (.com)](https://img.shields.io/travis/com/mychewcents/e2e-encryption)
![npm](https://img.shields.io/npm/v/e2e-encryption)
![Coveralls github](https://img.shields.io/coveralls/github/mychewcents/e2e-encryption)
![GitHub repo size](https://img.shields.io/github/repo-size/mychewcents/e2e-encryption)
![NPM](https://img.shields.io/npm/l/e2e-encryption)
![GitHub last commit](https://img.shields.io/github/last-commit/mychewcents/e2e-encryption)

## Overview

The primary aim of this package is to provide easier End-2-End encryption for the `client-side` web applications. This package is a wrapper around the original `tweetnacl` NPM package and uses its functions and object definitions internally.

## Installation

You can install `e2e-encryption` via a package manager:

[NPM](https://www.npmjs.org/):

```
$ npm install e2e-encryption
```

or [download source code](https://github.com/mychewcents/e2e-encryption).

## Usage

Internally uses the _x25519-xsalsa20-poly1305_ algorithm, that has been implemented by `tweetnacl` package.

#### new E2E(publicKey, privateKey, options)

Generates a new random key pair for object if `publicKey` or `privateKey` arguments are empty and returns it as an object:

```javascript
const instance = new E2E('', '', {});
```

Attributes and function calls supported by the object:

```
{
  publicKey: ...,
  privateKey: ...,
  Encrypt: (plainText, receiverPublicKey, options),
  Decrypt: (cipherText, senderPublicKey, options),
}
```

`Options` attributes allows you to set the flag to use same symmetric keys for the same client everytime.

```
{
  useSameKeyPerClient: true / false
}
```

#### Encrypt (payload, receiverPublicKey, options)

Generates the encrypted text using a symmetric key generated / used automatically in the internal execution which depends on the local `options` object passed above or the global `options` object, that was used during the instance creation.

> NOTE: The `payload` should always be a `JSON` object.

```javascript
const encryptedText = sender.Encrypt({ Hello: 'World' }, receiverPublicKey, {
  useSameKeyPerClient: true,
});
```

`encryptedText` contains the payload that was encrypted and is appended by the Symmetric Key, used to encrypt the payload, encrypted by the `sender's private key` and `receiver's public key`.

```
<Encrypted Payload>.<Encrypted Symmetric Key>
```

Local `Options` object passed here takes precedence over the global `Options`.

#### Decrypt(cipherText, senderPublicKey, options)

Generates the decrypted text by extracting / using the symmetric key automatically which depends on the local `Options` object passed or the global `Options` object that was used during the instance creation.

```javascript
const DecryptedText = receiver.Decrypt(
  '<encrypted payload>.<encrypted symmetric key>',
  senderPublicKey,
  {
    useSameKeyPerClient: true,
  },
);
```

`DecryptedText` is the `JSON` object that was encrypted.

```
{ Hello: 'World' }
```

Local `Options` object passed takes precedence over the global `Options` passed.

The function will throw an error if:

- Payload has been tampered with
- Encrypted Symmetric Key has been modified
- Pass the option to use already present symmetric key but the payload was encrypted using a different symmetric key

## Development and Testing

Install NPM modules needed for development:

    $ npm install

To build minified versions:

    $ npm build

### Testing

To run tests:

    $ npm test

## In Progress Tasks

- [ ] Allow for import of symmetric keys that might have been defined already
- [ ] Better error handling
- [ ] Most customizations for the symmetric keys and private/public keys
