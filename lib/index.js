"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports["default"] = void 0;

function asyncGeneratorStep(gen, resolve, reject, _next, _throw, key, arg) { try { var info = gen[key](arg); var value = info.value; } catch (error) { reject(error); return; } if (info.done) { resolve(value); } else { Promise.resolve(value).then(_next, _throw); } }

function _asyncToGenerator(fn) { return function () { var self = this, args = arguments; return new Promise(function (resolve, reject) { var gen = fn.apply(self, args); function _next(value) { asyncGeneratorStep(gen, resolve, reject, _next, _throw, "next", value); } function _throw(err) { asyncGeneratorStep(gen, resolve, reject, _next, _throw, "throw", err); } _next(undefined); }); }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } }

function _createClass(Constructor, protoProps, staticProps) { if (protoProps) _defineProperties(Constructor.prototype, protoProps); if (staticProps) _defineProperties(Constructor, staticProps); return Constructor; }

var crypto = require('crypto');

var util = require('util');

var GenerateKeyPair = util.promisify(crypto.generateKeyPair);

var E2E = /*#__PURE__*/function () {
  /**
   * Initializing the object with the private/public key pair.
   * If the public/private key pair is not present, the constructor
   * would create a new key pair for the user.
   *
   * @param {String | undefined} publicKey Public Key of the Host
   * @param {String | undefined} privateKey Private Key of the Host
   */
  function E2E(publicKey, privateKey) {
    _classCallCheck(this, E2E);

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


  _createClass(E2E, [{
    key: "Encrypt",
    value: function Encrypt(plaintext, clientPublicKey) {
      var iv = crypto.randomBytes(16);
      var symKey = this.CreateAndEncryptSymmetricKey(clientPublicKey);
      var cipher = crypto.createCipheriv('aes-256-gcm', symKey.raw, iv);
      var data = typeof plaintext === 'string' ? plaintext : JSON.stringify(plaintext);
      return "".concat(cipher.update(data, 'utf8', 'base64')).concat(cipher["final"]('base64'), ".").concat(iv.toString('base64'), ".").concat(symKey.enc).toString();
    }
    /**
     * Decrypt the payload received
     *
     * @param {String} cipherText Encrypted Payload
     */

  }, {
    key: "Decrypt",
    value: function Decrypt(cipherText) {
      var dataParts = cipherText.split('.');
      var decryptedSymKey = this.DecryptSymmetricKey(dataParts[2]);
      var decipher = crypto.createDecipheriv('aes-256-gcm', decryptedSymKey, dataParts[1]);
      return "".concat(decipher.update(dataParts[0], 'base64', 'utf8')).concat(decipher["final"]('utf8')).toString();
    }
    /**
     * Generates a new Symmetric Key for encryption and
     * encrypted Symmetric Key for Transmission.
     *
     * @param {String} clientPublicKey Client's PEM Encoded Public Key
     */

  }, {
    key: "CreateAndEncryptSymmetricKey",
    value: function CreateAndEncryptSymmetricKey(clientPublicKey) {
      var pubKeyObject = crypto.createPublicKey(clientPublicKey);
      var random = crypto.randomBytes(32);
      var rawSymmetricKey = crypto.createSecretKey(random);
      var encryptedSymmetricKey = crypto.publicEncrypt(pubKeyObject, rawSymmetricKey);
      return {
        raw: rawSymmetricKey.toString(),
        enc: encryptedSymmetricKey.toString()
      };
    }
    /**
     *
     * @param {String} encSymKey Encrypted Symmetric Key
     */

  }, {
    key: "DecryptSymmetricKey",
    value: function DecryptSymmetricKey(encSymKey) {
      return crypto.privateDecrypt(this.privateKey, encSymKey).toString();
    }
    /**
     * Generate a new Key Pair incase the user needs one.
     *
     * @param {String} passphrase Secret used to unlock the private key
     */

  }, {
    key: "GenerateNewKeys",
    value: function () {
      var _GenerateNewKeys = _asyncToGenerator( /*#__PURE__*/regeneratorRuntime.mark(function _callee(passphrase) {
        var newKey;
        return regeneratorRuntime.wrap(function _callee$(_context) {
          while (1) {
            switch (_context.prev = _context.next) {
              case 0:
                _context.next = 2;
                return GenerateKeyPair('ec', {
                  namedCurve: 'secp256k1',
                  publicKeyEncoding: {
                    type: 'spki',
                    format: 'pem'
                  },
                  privateKeyEncoding: {
                    type: 'pkcs8',
                    format: 'pem',
                    cipher: 'aes-256-cbc',
                    passphrase: passphrase
                  }
                });

              case 2:
                newKey = _context.sent;
                this.PublicKey(newKey.publicKey);
                this.PrivateKey(newKey.privateKey);

              case 5:
              case "end":
                return _context.stop();
            }
          }
        }, _callee, this);
      }));

      function GenerateNewKeys(_x) {
        return _GenerateNewKeys.apply(this, arguments);
      }

      return GenerateNewKeys;
    }()
    /**
     * @param {String} privateKey PEM Encoded Private Key
     */

  }, {
    key: "PrivateKey",
    set: function set(privateKey) {
      this.privateKey = crypto.createPrivateKey(privateKey);
    }
    /**
     * @param {String} publicKey PEM Encoded Public Key
     */
    ,

    /**
     * Get the Private Key of the object
     */
    get: function get() {
      return this.privateKey.toString();
    }
    /**
     * Get the Public Key of the object
     */

  }, {
    key: "PublicKey",
    set: function set(publicKey) {
      this.publicKey = crypto.createPublicKey(publicKey);
    },
    get: function get() {
      return this.publicKey.toString();
    }
  }]);

  return E2E;
}();

var _default = E2E;
exports["default"] = _default;