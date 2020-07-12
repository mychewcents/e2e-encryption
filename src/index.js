const crypto = require('crypto');
const util = require('util');

const GenerateKeyPair = util.promisify(crypto.generateKeyPair);

class E2E {
  /**
   * Initializing the object with the private/public key pair.
   * If the public/private key pair is not present, the constructor
   * would create a new key pair for the user.
   *
   * @param {String | undefined} publicKey Public Key of the Host
   * @param {String | undefined} privateKey Private Key of the Host
   */
  constructor(publicKey, privateKey) {
    if (publicKey !== undefined && privateKey !== undefined) {
      this.PublicKey(publicKey);
      this.PrivateKey(privateKey);
    } else {
      this.GenerateNewKeys();
    }
  }

  /**
   * @param {String | Object} plaintext Object to be encrypted
   * @param {String} clientPublicKey Client's PEM Encoded Public Key
   */
  Encrypt(plaintext, clientPublicKey) {
    const iv = crypto.randomBytes(16);
    const symKey = this.CreateAndEncryptSymmetricKey(clientPublicKey);

    const cipher = crypto.createCipheriv('aes-256-gcm', symKey.raw, iv);

    const data =
      typeof plaintext === 'string' ? plaintext : JSON.stringify(plaintext);

    return `${cipher.update(data, 'utf8', 'base64')}${cipher.final(
      'base64',
    )}.${iv.toString('base64')}.${symKey.enc}`.toString();
  }

  /**
   * Decrypt the payload received
   *
   * @param {String} cipherText Encrypted Payload
   */
  Decrypt(cipherText) {
    const dataParts = cipherText.split('.');
    const decryptedSymKey = this.DecryptSymmetricKey(dataParts[2]);

    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      decryptedSymKey,
      dataParts[1],
    );

    return `${decipher.update(dataParts[0], 'base64', 'utf8')}${decipher.final(
      'utf8',
    )}`.toString();
  }

  /**
   * Generates a new Symmetric Key for encryption and
   * encrypted Symmetric Key for Transmission.
   *
   * @param {String} clientPublicKey Client's PEM Encoded Public Key
   */
  CreateAndEncryptSymmetricKey(clientPublicKey) {
    const pubKeyObject = crypto.createPublicKey(clientPublicKey);

    const random = crypto.randomBytes(32);
    const rawSymmetricKey = crypto.createSecretKey(random);

    const encryptedSymmetricKey = crypto.publicEncrypt(
      pubKeyObject,
      rawSymmetricKey,
    );

    return {
      raw: rawSymmetricKey.toString(),
      enc: encryptedSymmetricKey.toString(),
    };
  }

  /**
   *
   * @param {String} encSymKey Encrypted Symmetric Key
   */
  DecryptSymmetricKey(encSymKey) {
    return crypto.privateDecrypt(this.privateKey, encSymKey).toString();
  }

  /**
   * Generate a new Key Pair incase the user needs one.
   *
   * @param {String} passphrase Secret used to unlock the private key
   */
  async GenerateNewKeys(passphrase) {
    const newKey = await GenerateKeyPair('ec', {
      namedCurve: 'secp256k1',
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem',
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
        cipher: 'aes-256-cbc',
        passphrase,
      },
    });

    this.PublicKey(newKey.publicKey);
    this.PrivateKey(newKey.privateKey);
  }

  /**
   * @param {String} privateKey PEM Encoded Private Key
   */
  set PrivateKey(privateKey) {
    this.privateKey = crypto.createPrivateKey(privateKey);
  }

  /**
   * @param {String} publicKey PEM Encoded Public Key
   */
  set PublicKey(publicKey) {
    this.publicKey = crypto.createPublicKey(publicKey);
  }

  /**
   * Get the Private Key of the object
   */
  get PrivateKey() {
    return this.privateKey.toString();
  }

  /**
   * Get the Public Key of the object
   */
  get PublicKey() {
    return this.publicKey.toString();
  }
}

export default E2E;
