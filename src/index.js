import { secretbox, box, randomBytes } from 'tweetnacl';
import {
  decodeUTF8,
  encodeUTF8,
  encodeBase64,
  decodeBase64,
} from 'tweetnacl-util';

const newNonceS = () => randomBytes(secretbox.nonceLength);
const newNonceA = () => randomBytes(box.nonceLength);

class E2E {
  /**
   * Initializing the object with the private/public key pair.
   * If the public/private key pair is not present, the constructor
   * would create a new key pair for the user.
   *
   * @param {String} publicKey Public Key of the Host
   * @param {String} privateKey Private Key of the Host
   * @param {String} options Options to configure the package
   */
  constructor(publicKey, privateKey, options) {
    if (
      publicKey !== undefined &&
      publicKey.length &&
      privateKey !== undefined &&
      privateKey.length
    ) {
      this.PublicKey(publicKey);
      this.PrivateKey(privateKey);
    } else {
      this.GenerateNewKeys();
    }

    if (options) {
      this.options = options;
    }
  }

  /**
   * @param {Object} plainText JSON Object to be encrypted
   * @param {String} receiverPubKey Reveiver's Public Key in Base64
   * @param {Object} options Override the instance's properties
   */
  Encrypt(plainText, receiverPubKey, options) {
    let symmetricKey;

    if (
      !this.SymmetricKeys[receiverPubKey] ||
      (this.options && !this.options.useSameSymmetricKeyPerClient) ||
      (options && !options.useSameSymmetricKeyPerClient)
    ) {
      symmetricKey = this.EncryptSymmetricKey(receiverPubKey);
      this.SymmetricKeys[receiverPubKey] = symmetricKey;
    } else {
      symmetricKey = this.SymmetricKeys[receiverPubKey];
    }

    const nonce = newNonceS();
    const keyUint8Array = decodeBase64(symmetricKey.raw);

    if (typeof plaintext !== 'object') {
      throw new Error('Only JSON object accepted as an input.');
    }

    const messageUint8 = decodeUTF8(JSON.stringify(plainText));
    const newBox = secretbox(messageUint8, nonce, keyUint8Array);

    const fullMessage = new Uint8Array(nonce.length + newBox.length);
    fullMessage.set(nonce);
    fullMessage.set(newBox, nonce.length);

    const fullMessageAsBase64 = encodeBase64(fullMessage);

    return `${fullMessageAsBase64}.${symmetricKey.enc}`;
  }

  /**
   * Decrypt the payload received
   *
   * @param {String} cipherText Encrypted Payload
   * @param {String} senderPublicKey Sender's Public Key
   * @param {Object} options Override the instance's properties
   */
  Decrypt(cipherText, senderPublicKey, options) {
    const dataParts = cipherText.split('.');
    if (dataParts.length !== 2) {
      throw new Error('Payload is corrupted.');
    }

    let symmetricKey;

    if (
      !this.SymmetricKeys[senderPublicKey] ||
      (this.options && !this.options.useSameSymmetricKeyPerClient) ||
      (options && !options.useSameSymmetricKeyPerClient)
    ) {
      symmetricKey = this.DecryptSymmetricKey(dataParts[1], senderPublicKey);
      this.SymmetricKeys[senderPublicKey] = symmetricKey;
    } else {
      symmetricKey = this.SymmetricKeys[senderPublicKey];
    }

    const keyUint8Array = decodeBase64(symmetricKey);
    const messageWithNonceAsUint8Array = decodeBase64(dataParts[0]);

    const nonce = messageWithNonceAsUint8Array.slice(0, secretbox.nonceLength);
    const message = messageWithNonceAsUint8Array.slice(
      secretbox.nonceLength,
      dataParts[0].length,
    );

    const decrypted = secretbox.open(message, nonce, keyUint8Array);

    if (!decrypted) {
      throw new Error('Could not decrypt message');
    }

    const base64DecryptedMessage = encodeUTF8(decrypted);
    return JSON.parse(base64DecryptedMessage);
  }

  /**
   * Generates a new Symmetric Key for encryption and
   * encrypted Symmetric Key for Transmission.
   *
   * @param {String} publicKey Receiver's public key
   */
  EncryptSymmetricKey(publicKey) {
    const symmetricKey = encodeBase64(randomBytes(secretbox.keyLength));

    const nonce = newNonceA();
    const finalKey = this.GetShared(publicKey);
    const pubKeyAsUint8Array = decodeBase64(finalKey);

    const messageUint8 = decodeUTF8(JSON.stringify({ key: symmetricKey }));

    const encrypted = box.after(messageUint8, nonce, pubKeyAsUint8Array);

    const fullMessage = new Uint8Array(nonce.length + encrypted.length);
    fullMessage.set(nonce);
    fullMessage.set(encrypted, nonce.length);

    return {
      raw: symmetricKey,
      enc: encodeBase64(fullMessage),
    };
  }

  /**
   * Decrypt the Symmetric Key
   *
   * @param {String} messageWithNonce Encrypted Payload
   * @param {String} publicKey Sender's Public Key
   */
  DecryptSymmetricKey(messageWithNonce, publicKey) {
    const finalKey = this.GetShared(publicKey);
    const privateKeyAsUint8Array = decodeBase64(finalKey);
    const messageWithNonceAsUint8Array = decodeBase64(messageWithNonce);
    const nonce = messageWithNonceAsUint8Array.slice(0, box.nonceLength);
    const message = messageWithNonceAsUint8Array.slice(
      box.nonceLength,
      messageWithNonce.length,
    );

    const decrypted = box.open.after(message, nonce, privateKeyAsUint8Array);

    if (!decrypted) {
      throw new Error('Could not decrypt the key.');
    }

    const jsonObject = JSON.parse(encodeUTF8(decrypted));

    return jsonObject.key;
  }

  /**
   * Generate the shared encryption key for the Symmetric keys
   *
   * @param {String} pub Receiver's Public Key
   */
  GetShared(publicKey) {
    const publicKeyAsUint8Array = decodeBase64(publicKey);
    const privateKeyAsUint8Array = decodeBase64(this.privateKey);

    return encodeBase64(
      box.before(publicKeyAsUint8Array, privateKeyAsUint8Array),
    );
  }

  /**
   * Generate a new Key Pair incase the user needs one.
   */
  GenerateNewKeys() {
    const newKey = box.keyPair();

    this.publicKey = encodeBase64(newKey.publicKey);
    this.privateKey = encodeBase64(newKey.secretKey);
  }

  /**
   * @param {String} privateKey Base64 Private Key
   */
  set PrivateKey(privateKey) {
    this.privateKey = privateKey;
  }

  /**
   * @param {String} publicKey Base64 Public Key
   */
  set PublicKey(publicKey) {
    this.publicKey = publicKey;
  }

  /**
   * Get the Private Key of the object
   */
  get PrivateKey() {
    return this.privateKey;
  }

  /**
   * Get the Public Key of the object
   */
  get PublicKey() {
    return this.publicKey;
  }

  /**
   * Get the Symmetric Keys Dictionary
   */
  get SymmmetricKey() {
    return this.SymmetricKeys;
  }
}

export default E2E;
