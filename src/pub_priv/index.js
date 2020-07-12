import elliptic from 'elliptic';
import crypto from 'crypto';
import AES from 'crypto-js/aes';

class KeyPair {
  pubKeysMap;

  /**
   * Allows the user to define the key curve that
   * they plan to use. Only 'elliptic' package
   * curves are supported.
   *
   * @param {string | elliptic.curves.PresetCurve} options Key's Curve value
   */
  constructor(options) {
    this.EC = elliptic.ec;
    this.ec = new this.EC(options);
    this.key = this.EC.genKeyPair();
  }

  /**
   * Allowing the user to set the key that they might
   * have created outside this package.
   *
   * @param {elliptic.ec.KeyPair} key Elliptic KeyPair instance
   */
  set Key(key) {
    const check = key.validate();
    if (check.result) {
      this.key = key;
    }
  }

  /**
   * Allow the user to generate the key for the public key they pass
   *
   * @param {String} pub Public Key Hex string of the receiver
   */
  GetNewSymKey(pub) {
    const symKey = crypto.randomBytes(32).toString();
    const key = this.ec.keyFromPublic(pub);

    const keySig = this.ec.sign(symKey, key);
    return { key: symKey, sig: keySig };
  }

  /**
   * Allow the host to decrypt the received message
   *
   * @param {String} priv Private Key Hex string of the host
   */
  GetDecryptedSymKey(priv) {
    const key = this.ec.keyFromPrivate(priv);
    key.
  }

  /**
   * 
   * @param {String} symKey Symmetric key to use to encrypt the data
   * @param {String | Object} plainText Data to be encrypted 
   */
  EncryptData(symKey, plainText) {
    const data = typeof plainText === 'string' ? plainText : JSON.stringify(plainText);
    const encrypted = AES.encrypt(data);
    encrypted.
    return AES.encrypt(plainText, symKey).toString();
  }
}

export default KeyPair;
