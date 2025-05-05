import crypto from "crypto";

export class KeyPair {
  constructor(
    public publicKey: crypto.KeyObject,
    public privateKey: crypto.KeyObject
  ) {}
}

export class KeyService {
  generateX25519KeyPair() {
    const keyPair = crypto.generateKeyPairSync("x25519");
    const privateKey = keyPair.privateKey;
    const publicKey = keyPair.publicKey;

    return new KeyPair(publicKey, privateKey);
  }

  generateCommonSecret(
    privateKey: crypto.KeyObject,
    publicKey: crypto.KeyObject
  ) {
    const commonKey = crypto.diffieHellman({
      privateKey,
      publicKey,
    });

    return commonKey;
  }

  extractRawKeyFromDerFormat(key: crypto.KeyObject) {
    const keyType = key.type === "public" ? "spki" : "pkcs8";
    const keyDer = key.export({
      type: keyType,
      format: "der",
    });
    // NOTE: 末尾の32バイト分が生の公開鍵データになる
    const rawKey = keyDer.slice(keyDer.length - 32);

    // 生の公開鍵を16進数文字列に変換
    return rawKey.toString("hex");
  }

  encodeX25519PublicKeyToDer(publicKeyBytes: Buffer) {
    if (publicKeyBytes.length !== 32) {
      throw new Error("公開鍵は32バイトである必要があります");
    }
    const subjectPublicKeyInfo = Buffer.concat([
      Buffer.from([0x30, 0x2a]), // SEQUENCE (42 bytes)
      Buffer.from([0x30, 0x05]), // SEQUENCE (5 bytes)
      Buffer.from([0x06, 0x03]), // OBJECT IDENTIFIER (3 bytes)
      Buffer.from([0x2b, 0x65, 0x6e]), // X25519 OID
      Buffer.from([0x03, 0x21, 0x00]), // BIT STRING (33 bytes)
      publicKeyBytes,
    ]);
    return crypto.createPublicKey({
      key: subjectPublicKeyInfo,
      type: "spki",
      format: "der",
    });
  }
}
