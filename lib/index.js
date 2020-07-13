"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports["default"] = void 0;

var _tweetnacl = require("tweetnacl");

var _tweetnaclUtil = require("tweetnacl-util");

function _typeof(obj) { "@babel/helpers - typeof"; if (typeof Symbol === "function" && typeof Symbol.iterator === "symbol") { _typeof = function _typeof(obj) { return typeof obj; }; } else { _typeof = function _typeof(obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; }; } return _typeof(obj); }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } }

function _createClass(Constructor, protoProps, staticProps) { if (protoProps) _defineProperties(Constructor.prototype, protoProps); if (staticProps) _defineProperties(Constructor, staticProps); return Constructor; }

var newNonceS = function newNonceS() {
  return (0, _tweetnacl.randomBytes)(_tweetnacl.secretbox.nonceLength);
};

var newNonceA = function newNonceA() {
  return (0, _tweetnacl.randomBytes)(_tweetnacl.box.nonceLength);
};

var E2E = /*#__PURE__*/function () {
  /**
   * Initializing the object with the private/public key pair.
   * If the public/private key pair is not present, the constructor
   * would create a new key pair for the user.
   *
   * @param {String} publicKey Public Key of the Host
   * @param {String} privateKey Private Key of the Host
   * @param {String} options Options to configure the package
   */
  function E2E(publicKey, privateKey, options) {
    _classCallCheck(this, E2E);

    if (publicKey !== undefined && publicKey.length && privateKey !== undefined && privateKey.length) {
      this.publicKey = publicKey;
      this.privateKey = privateKey;
    } else {
      this.GenerateNewKeys();
    }

    if (Object.keys(options).length) {
      this.options = options;
    } else {
      this.options = {
        useSameKeyPerClient: false
      };
    }

    this.SymmetricKeys = {};
  }
  /**
   * @param {Object} plainText JSON Object to be encrypted
   * @param {String} receiverPubKey Reveiver's Public Key in Base64
   * @param {Object} options Override the instance's properties
   */


  _createClass(E2E, [{
    key: "Encrypt",
    value: function Encrypt(plainText, receiverPubKey, options) {
      var symmetricKey;
      var useSameKey = options.useSameKeyPerClient !== undefined ? options.useSameKeyPerClient : this.options.useSameKeyPerClient;

      if (!this.SymmetricKeys[receiverPubKey] || !useSameKey) {
        symmetricKey = this.EncryptSymmetricKey(receiverPubKey);

        if (useSameKey) {
          this.SymmetricKeys[receiverPubKey] = symmetricKey;
        }
      } else {
        symmetricKey = this.SymmetricKeys[receiverPubKey];
      }

      var nonce = newNonceS();
      var keyUint8Array = (0, _tweetnaclUtil.decodeBase64)(symmetricKey.raw);

      if (_typeof(plainText) !== 'object') {
        throw new Error('Only JSON object accepted as an input');
      }

      var messageUint8 = (0, _tweetnaclUtil.decodeUTF8)(JSON.stringify(plainText));
      var newBox = (0, _tweetnacl.secretbox)(messageUint8, nonce, keyUint8Array);
      var fullMessage = new Uint8Array(nonce.length + newBox.length);
      fullMessage.set(nonce);
      fullMessage.set(newBox, nonce.length);
      var fullMessageAsBase64 = (0, _tweetnaclUtil.encodeBase64)(fullMessage);
      return "".concat(fullMessageAsBase64, ".").concat(symmetricKey.enc);
    }
    /**
     * Decrypt the payload received
     *
     * @param {String} cipherText Encrypted Payload
     * @param {String} senderPublicKey Sender's Public Key
     * @param {Object} options Override the instance's properties
     */

  }, {
    key: "Decrypt",
    value: function Decrypt(cipherText, senderPublicKey, options) {
      var dataParts = cipherText.split('.');

      if (dataParts.length !== 2) {
        throw new Error('Payload is corrupted');
      }

      var symmetricKey;
      var useSameKey = options.useSameKeyPerClient !== undefined ? options.useSameKeyPerClient : this.options.useSameKeyPerClient;

      if (!this.SymmetricKeys[senderPublicKey] || !useSameKey) {
        symmetricKey = this.DecryptSymmetricKey(dataParts[1], senderPublicKey);

        if (useSameKey) {
          this.SymmetricKeys[senderPublicKey] = symmetricKey;
        }
      } else {
        symmetricKey = this.SymmetricKeys[senderPublicKey];
      }

      var keyUint8Array = (0, _tweetnaclUtil.decodeBase64)(symmetricKey);
      var messageWithNonceAsUint8Array = (0, _tweetnaclUtil.decodeBase64)(dataParts[0]);
      var nonce = messageWithNonceAsUint8Array.slice(0, _tweetnacl.secretbox.nonceLength);
      var message = messageWithNonceAsUint8Array.slice(_tweetnacl.secretbox.nonceLength, dataParts[0].length);

      var decrypted = _tweetnacl.secretbox.open(message, nonce, keyUint8Array);

      if (!decrypted) {
        throw new Error('Could not decrypt message');
      }

      var base64DecryptedMessage = (0, _tweetnaclUtil.encodeUTF8)(decrypted);
      return JSON.parse(base64DecryptedMessage);
    }
    /**
     * Generates a new Symmetric Key for encryption and
     * encrypted Symmetric Key for Transmission.
     *
     * @param {String} publicKey Receiver's public key
     */

  }, {
    key: "EncryptSymmetricKey",
    value: function EncryptSymmetricKey(publicKey) {
      var symmetricKey = (0, _tweetnaclUtil.encodeBase64)((0, _tweetnacl.randomBytes)(_tweetnacl.secretbox.keyLength));
      var nonce = newNonceA();
      var finalKey = this.GetShared(publicKey);
      var pubKeyAsUint8Array = (0, _tweetnaclUtil.decodeBase64)(finalKey);
      var messageUint8 = (0, _tweetnaclUtil.decodeUTF8)(JSON.stringify({
        key: symmetricKey
      }));

      var encrypted = _tweetnacl.box.after(messageUint8, nonce, pubKeyAsUint8Array);

      var fullMessage = new Uint8Array(nonce.length + encrypted.length);
      fullMessage.set(nonce);
      fullMessage.set(encrypted, nonce.length);
      return {
        raw: symmetricKey,
        enc: (0, _tweetnaclUtil.encodeBase64)(fullMessage)
      };
    }
    /**
     * Decrypt the Symmetric Key
     *
     * @param {String} messageWithNonce Encrypted Payload
     * @param {String} publicKey Sender's Public Key
     */

  }, {
    key: "DecryptSymmetricKey",
    value: function DecryptSymmetricKey(messageWithNonce, publicKey) {
      var finalKey = this.GetShared(publicKey);
      var privateKeyAsUint8Array = (0, _tweetnaclUtil.decodeBase64)(finalKey);
      var messageWithNonceAsUint8Array = (0, _tweetnaclUtil.decodeBase64)(messageWithNonce);
      var nonce = messageWithNonceAsUint8Array.slice(0, _tweetnacl.box.nonceLength);
      var message = messageWithNonceAsUint8Array.slice(_tweetnacl.box.nonceLength, messageWithNonce.length);

      var decrypted = _tweetnacl.box.open.after(message, nonce, privateKeyAsUint8Array);

      if (!decrypted) {
        throw new Error('Could not decrypt the key');
      }

      var jsonObject = JSON.parse((0, _tweetnaclUtil.encodeUTF8)(decrypted));
      return jsonObject.key;
    }
    /**
     * Generate the shared encryption key for the Symmetric keys
     *
     * @param {String} pub Receiver's Public Key
     */

  }, {
    key: "GetShared",
    value: function GetShared(publicKey) {
      var publicKeyAsUint8Array = (0, _tweetnaclUtil.decodeBase64)(publicKey);
      var privateKeyAsUint8Array = (0, _tweetnaclUtil.decodeBase64)(this.privateKey);
      return (0, _tweetnaclUtil.encodeBase64)(_tweetnacl.box.before(publicKeyAsUint8Array, privateKeyAsUint8Array));
    }
    /**
     * Generate a new Key Pair incase the user needs one.
     */

  }, {
    key: "GenerateNewKeys",
    value: function GenerateNewKeys() {
      var newKey = _tweetnacl.box.keyPair();

      this.publicKey = (0, _tweetnaclUtil.encodeBase64)(newKey.publicKey);
      this.privateKey = (0, _tweetnaclUtil.encodeBase64)(newKey.secretKey);
    }
  }]);

  return E2E;
}();

var _default = E2E;
exports["default"] = _default;