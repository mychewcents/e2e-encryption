/* eslint-disable prefer-destructuring */
import E2E from '../src';

const DemoData = { data: 'Hello World' };

describe('Check the Object Instantiation', () => {
  it('should simply create a new object with keys', () => {
    const instance = new E2E('', '', {});

    expect(instance.publicKey.length).toBe(44);
    expect(instance.privateKey.length).toBe(44);
  });

  it('should initilize with the same keys and options', () => {
    const instance = new E2E('', '', {
      useSameKeyPerClient: false,
    });

    const newInstance = new E2E(
      instance.publicKey,
      instance.privateKey,
      instance.options,
    );

    expect(newInstance.publicKey).toBe(instance.publicKey);
    expect(newInstance.privateKey).toBe(instance.privateKey);
    expect(newInstance.options).toBe(instance.options);
  });
});

describe('Check the precedence when Global and Local OPTIONS are passed', () => {
  it('=> Global:UNDEFINED Local:UNDEFINED', () => {
    const host = new E2E('', '', {});
    const client = new E2E('', '', {});

    const encryptedText1 = host.Encrypt(DemoData, client.publicKey, {});
    const encryptedText2 = host.Encrypt(DemoData, client.publicKey, {});

    const encSymKey1 = encryptedText1.split('.')[1];
    const encSymKey2 = encryptedText2.split('.')[1];

    expect(encSymKey1 === encSymKey2).toBe(false);
  });

  it('=> Global:UNDEFINED Local:FALSE', () => {
    const host = new E2E('', '', {});
    const client = new E2E('', '', {});

    const encryptedText1 = host.Encrypt(DemoData, client.publicKey, {
      useSameKeyPerClient: false,
    });
    const encryptedText2 = host.Encrypt(DemoData, client.publicKey, {
      useSameKeyPerClient: false,
    });

    const encSymKey1 = encryptedText1.split('.')[1];
    const encSymKey2 = encryptedText2.split('.')[1];

    expect(encSymKey1 === encSymKey2).toBe(false);
  });

  it('=> Global:UNDEFINED Local:TRUE', () => {
    const host = new E2E('', '', {});
    const client = new E2E('', '', {});

    const encryptedText1 = host.Encrypt(DemoData, client.publicKey, {
      useSameKeyPerClient: true,
    });
    const encryptedText2 = host.Encrypt(DemoData, client.publicKey, {
      useSameKeyPerClient: true,
    });

    const encSymKey1 = encryptedText1.split('.')[1];
    const encSymKey2 = encryptedText2.split('.')[1];

    expect(encSymKey1 === encSymKey2).toBe(true);
  });

  it('=> Global:FALSE Local:UNDEFINED', () => {
    const host = new E2E('', '', { useSameKeyPerClient: false });
    const client = new E2E('', '', {});

    const encryptedText1 = host.Encrypt(DemoData, client.publicKey, {});
    const encryptedText2 = host.Encrypt(DemoData, client.publicKey, {});

    const encSymKey1 = encryptedText1.split('.')[1];
    const encSymKey2 = encryptedText2.split('.')[1];

    expect(encSymKey1 === encSymKey2).toBe(false);
  });

  it('=> Global:FALSE Local:FALSE', () => {
    const host = new E2E('', '', { useSameKeyPerClient: false });
    const client = new E2E('', '', {});

    const encryptedText1 = host.Encrypt(DemoData, client.publicKey, {
      useSameKeyPerClient: false,
    });
    const encryptedText2 = host.Encrypt(DemoData, client.publicKey, {
      useSameKeyPerClient: false,
    });

    const encSymKey1 = encryptedText1.split('.')[1];
    const encSymKey2 = encryptedText2.split('.')[1];

    expect(encSymKey1 === encSymKey2).toBe(false);
  });

  it('=> Global:FALSE Local:TRUE', () => {
    const host = new E2E('', '', { useSameKeyPerClient: false });
    const client = new E2E('', '', {});

    const encryptedText1 = host.Encrypt(DemoData, client.publicKey, {
      useSameKeyPerClient: true,
    });
    const encryptedText2 = host.Encrypt(DemoData, client.publicKey, {
      useSameKeyPerClient: true,
    });

    const encSymKey1 = encryptedText1.split('.')[1];
    const encSymKey2 = encryptedText2.split('.')[1];

    expect(encSymKey1 === encSymKey2).toBe(true);
  });

  it('=> Global:TRUE Local:UNDEFINED', () => {
    const host = new E2E('', '', { useSameKeyPerClient: true });
    const client = new E2E('', '', {});

    const encryptedText1 = host.Encrypt(DemoData, client.publicKey, {});
    const encryptedText2 = host.Encrypt(DemoData, client.publicKey, {});

    const encSymKey1 = encryptedText1.split('.')[1];
    const encSymKey2 = encryptedText2.split('.')[1];

    expect(encSymKey1 === encSymKey2).toBe(true);
  });

  it('=> Global:TRUE Local:FALSE', () => {
    const host = new E2E('', '', { useSameKeyPerClient: true });
    const client = new E2E('', '', {});

    const encryptedText1 = host.Encrypt(DemoData, client.publicKey, {
      useSameKeyPerClient: false,
    });
    const encryptedText2 = host.Encrypt(DemoData, client.publicKey, {
      useSameKeyPerClient: false,
    });

    const encSymKey1 = encryptedText1.split('.')[1];
    const encSymKey2 = encryptedText2.split('.')[1];

    expect(encSymKey1 === encSymKey2).toBe(false);
  });

  it('=> Global:TRUE Local:TRUE', () => {
    const host = new E2E('', '', { useSameKeyPerClient: true });
    const client = new E2E('', '', {});

    const encryptedText1 = host.Encrypt(DemoData, client.publicKey, {
      useSameKeyPerClient: true,
    });
    const encryptedText2 = host.Encrypt(DemoData, client.publicKey, {
      useSameKeyPerClient: true,
    });

    const encSymKey1 = encryptedText1.split('.')[1];
    const encSymKey2 = encryptedText2.split('.')[1];

    expect(encSymKey1 === encSymKey2).toBe(true);
  });
});

describe('Check the encryption when Local OPTIONS change across calls', () => {
  it('=> First:UNDEFINED Second:UNDEFINED/FALSE/TRUE', () => {
    const host = new E2E('', '', {});
    const client = new E2E('', '', {});

    let encryptedText1 = host.Encrypt(DemoData, client.publicKey, {});
    let encryptedText2 = host.Encrypt(DemoData, client.publicKey, {});

    let encSymKey1 = encryptedText1.split('.')[1];
    let encSymKey2 = encryptedText2.split('.')[1];

    expect(encSymKey1 === encSymKey2).toBe(false);

    encryptedText1 = host.Encrypt(DemoData, client.publicKey, {});
    encryptedText2 = host.Encrypt(DemoData, client.publicKey, {
      useSameKeyPerClient: false,
    });

    encSymKey1 = encryptedText1.split('.')[1];
    encSymKey2 = encryptedText2.split('.')[1];

    expect(encSymKey1 === encSymKey2).toBe(false);

    encryptedText1 = host.Encrypt(DemoData, client.publicKey, {});
    encryptedText2 = host.Encrypt(DemoData, client.publicKey, {
      useSameKeyPerClient: true,
    });

    encSymKey1 = encryptedText1.split('.')[1];
    encSymKey2 = encryptedText2.split('.')[1];

    expect(encSymKey1 === encSymKey2).toBe(false);
  });

  it('=> First:FALSE Second:UNDEFINED/FALSE/TRUE', () => {
    const host = new E2E('', '', {});
    const client = new E2E('', '', {});

    let encryptedText1 = host.Encrypt(DemoData, client.publicKey, {
      useSameKeyPerClient: false,
    });
    let encryptedText2 = host.Encrypt(DemoData, client.publicKey, {});

    let encSymKey1 = encryptedText1.split('.')[1];
    let encSymKey2 = encryptedText2.split('.')[1];

    expect(encSymKey1 === encSymKey2).toBe(false);

    encryptedText1 = host.Encrypt(DemoData, client.publicKey, {
      useSameKeyPerClient: false,
    });
    encryptedText2 = host.Encrypt(DemoData, client.publicKey, {
      useSameKeyPerClient: false,
    });

    encSymKey1 = encryptedText1.split('.')[1];
    encSymKey2 = encryptedText2.split('.')[1];

    expect(encSymKey1 === encSymKey2).toBe(false);

    encryptedText1 = host.Encrypt(DemoData, client.publicKey, {
      useSameKeyPerClient: false,
    });
    encryptedText2 = host.Encrypt(DemoData, client.publicKey, {
      useSameKeyPerClient: true,
    });

    encSymKey1 = encryptedText1.split('.')[1];
    encSymKey2 = encryptedText2.split('.')[1];

    expect(encSymKey1 === encSymKey2).toBe(false);
  });

  it('=> First:TRUE Second:UNDEFINED/FALSE', () => {
    const host = new E2E('', '', {});
    const client = new E2E('', '', {});

    let encryptedText1 = host.Encrypt(DemoData, client.publicKey, {
      useSameKeyPerClient: true,
    });
    let encryptedText2 = host.Encrypt(DemoData, client.publicKey, {});

    let encSymKey1 = encryptedText1.split('.')[1];
    let encSymKey2 = encryptedText2.split('.')[1];

    expect(encSymKey1 === encSymKey2).toBe(false);

    encryptedText1 = host.Encrypt(DemoData, client.publicKey, {
      useSameKeyPerClient: true,
    });
    encryptedText2 = host.Encrypt(DemoData, client.publicKey, {
      useSameKeyPerClient: false,
    });

    encSymKey1 = encryptedText1.split('.')[1];
    encSymKey2 = encryptedText2.split('.')[1];

    expect(encSymKey1 === encSymKey2).toBe(false);
  });

  it('=> First:TRUE Second:TRUE', () => {
    const host = new E2E('', '', {});
    const client = new E2E('', '', {});

    const encryptedText1 = host.Encrypt(DemoData, client.publicKey, {
      useSameKeyPerClient: true,
    });
    const encryptedText2 = host.Encrypt(DemoData, client.publicKey, {
      useSameKeyPerClient: true,
    });

    const encSymKey1 = encryptedText1.split('.')[1];
    const encSymKey2 = encryptedText2.split('.')[1];

    expect(encSymKey1 === encSymKey2).toBe(true);
  });
});

describe('Decrypt the received Payload', () => {
  it('should decrypt the object', () => {
    const host = new E2E('', '', {});
    const client = new E2E('', '', {});

    const encryptedText1 = host.Encrypt(DemoData, client.publicKey, {});
    const decryptedText1 = client.Decrypt(encryptedText1, host.publicKey, {});

    expect(JSON.stringify(decryptedText1)).toBe(JSON.stringify(DemoData));
  });

  it('should throw decrypt error because using the same key as before', () => {
    const host = new E2E('', '', {});
    const client = new E2E('', '', {});

    const encryptedText1 = host.Encrypt(DemoData, client.publicKey, {});
    const encryptedText2 = host.Encrypt(DemoData, client.publicKey, {});

    try {
      client.Decrypt(encryptedText1, host.publicKey, {
        useSameKeyPerClient: true,
      });

      client.Decrypt(encryptedText2, host.publicKey, {
        useSameKeyPerClient: true,
      });
    } catch (e) {
      expect(e.message).toBe('Could not decrypt message');
    }
  });

  it('should not throw any error even when passing options', () => {
    const host = new E2E('', '', {});
    const client = new E2E('', '', {});

    const encryptedText1 = host.Encrypt(DemoData, client.publicKey, {});
    const encryptedText2 = host.Encrypt(DemoData, client.publicKey, {});

    try {
      client.Decrypt(encryptedText1, host.publicKey, {
        useSameKeyPerClient: true,
      });

      client.Decrypt(encryptedText2, host.publicKey, {
        useSameKeyPerClient: false,
      });

      expect(true).toBe(true);
    } catch (e) {
      expect(e.message).toBe('Could not decrypt message');
    }
  });

  it('should throw Payload corrupted error.', () => {
    const host = new E2E('', '', {});
    const client = new E2E('', '', {});

    const encryptedText1 = host.Encrypt(DemoData, client.publicKey, {});

    try {
      client.Decrypt(encryptedText1.split('.')[1], host.publicKey, {
        useSameKeyPerClient: true,
      });
      expect(true).toBe(true);
    } catch (e) {
      expect(e.message).toBe('Payload is corrupted');
    }
  });

  it('should throw invalid encoding for the Symmetric Key error', () => {
    const host = new E2E('', '', {});
    const client = new E2E('', '', {});

    const encryptedText1 = host.Encrypt(DemoData, client.publicKey, {});

    const corruptedEncryptedText = `${encryptedText1}=`;

    try {
      client.Decrypt(corruptedEncryptedText, host.publicKey, {
        useSameKeyPerClient: true,
      });
      expect(true).toBe(true);
    } catch (e) {
      expect(e.message).toBe('invalid encoding');
    }
  });

  it('should throw Encrypted Symmetric Key corrupted error', () => {
    const host = new E2E('', '', {});
    const client = new E2E('', '', {});

    const encryptedText1 = host.Encrypt(DemoData, client.publicKey, {});

    const data = encryptedText1.split('.');
    data[1] = data[1].replace(data[1].substring(1, 2), 'A');

    const corruptedEncryptedText = data.join('.');

    try {
      client.Decrypt(corruptedEncryptedText, host.publicKey, {
        useSameKeyPerClient: true,
      });
      expect(true).toBe(true);
    } catch (e) {
      expect(e.message).toBe('Could not decrypt the key');
    }
  });
});

describe('Encrypting the Payload', () => {
  it('should encrypt the object', () => {
    const host = new E2E('', '', {});
    const client = new E2E('', '', {});

    try {
      host.Encrypt(DemoData, client.publicKey, {});
      expect(true).toBe(true);
    } catch (e) {
      expect(e.message).toBe('Only JSON object accepted as an input');
    }
  });

  it('should encrypt the object', () => {
    const host = new E2E('', '', {});
    const client = new E2E('', '', {});

    try {
      host.Encrypt(JSON.stringify(DemoData), client.publicKey, {});
      expect(true).toBe(true);
    } catch (e) {
      expect(e.message).toBe('Only JSON object accepted as an input');
    }
  });
});
