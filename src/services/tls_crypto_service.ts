import crypto from "crypto";

export class TlsCryptoService {
  private hashAlgorithm: string;

  constructor() {
    this.hashAlgorithm = "sha384";
  }

  hkdfExtract(salt: Buffer, ikm: Buffer) {
    const hmac = crypto.createHmac(this.hashAlgorithm, salt);
    hmac.update(ikm);
    return hmac.digest();
  }

  hkdfExpand(prk: Buffer, info: Buffer, length: number) {
    const hashLength = crypto.createHash(this.hashAlgorithm).digest().length;
    const n = Math.ceil(length / hashLength);
    let t = Buffer.alloc(0);
    let t_prev = Buffer.alloc(0);

    for (let i = 1; i <= n; i++) {
      const hmac = crypto.createHmac(this.hashAlgorithm, prk);
      const data = Buffer.concat([t_prev, info, Buffer.from([i])]);
      hmac.update(data);
      const t_n = hmac.digest();
      t = Buffer.concat([t, t_n]);
      t_prev = t_n;
    }

    return t.slice(0, length);
  }

  hkdfExpandLabel(
    secret: Buffer,
    label: string,
    context: Buffer,
    length: number
  ) {
    const hkdfLabel = new HkdfLabel(length, label, context).toPlainText();
    return this.hkdfExpand(secret, hkdfLabel, length);
  }

  transcriptHash(messages: Buffer) {
    return crypto.createHash(this.hashAlgorithm).update(messages).digest();
  }

  getHashLength() {
    return crypto.createHash(this.hashAlgorithm).digest().length;
  }

  deriveSecret(secret: Buffer, label: string, messages: Buffer) {
    const transcriptHash = this.transcriptHash(messages);
    const length = this.getHashLength();
    return this.hkdfExpandLabel(secret, label, transcriptHash, length);
  }

  aeadEncrypt(key: Buffer, nonce: Buffer, aad: Buffer, plaintext: Buffer) {
    const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
    cipher.setAAD(aad);
    // NOTE: plaintextと同じ長さで出力される
    const encryptedUpdate = cipher.update(plaintext);
    const encryptedFinal = cipher.final();

    const tag = cipher.getAuthTag();

    // 暗号文, 認証タグを連結
    const encryptedData = Buffer.concat([encryptedUpdate, encryptedFinal, tag]);

    return encryptedData;
  }

  // plaintext of encrypted_record =
  //   AEAD-Decrypt(peer_write_key, nonce,
  //     additional_data, AEADEncrypted)
  aeadDecrypt(
    ciphertext: Buffer,
    key: Buffer,
    nonce: Buffer,
    aad: Buffer,
    authTag: Buffer // GCM の認証タグ
  ) {
    try {
      const decipher = crypto.createDecipheriv("aes-256-gcm", key, nonce);
      decipher.setAAD(aad);
      decipher.setAuthTag(authTag);

      const plaintext = decipher.update(ciphertext);
      return Buffer.concat([plaintext, decipher.final()]);
    } catch (error) {
      console.error("AEAD decryption failed:", error);
      throw new Error("AEAD decryption failed");
    }
  }
}

class HkdfLabel {
  constructor(
    public length: number,
    public label: string,
    public context: Buffer
  ) {}

  toPlainText(): Buffer {
    const lengthBuffer = Buffer.alloc(2);
    lengthBuffer.writeUInt16BE(this.length, 0);

    const labelPrefix = "tls13 ";
    const fullLabel = labelPrefix + this.label;
    const labelBuffer = Buffer.from(fullLabel, "utf8");
    const labelLength = labelBuffer.length;
    const labelLengthBuffer = Buffer.alloc(1);
    labelLengthBuffer.writeUInt8(labelLength, 0);

    const contextLength = this.context.length;
    const contextLengthBuffer = Buffer.alloc(1);
    contextLengthBuffer.writeUInt8(contextLength, 0);

    const hkdfLabelBuffer = Buffer.concat([
      lengthBuffer,
      labelLengthBuffer,
      labelBuffer,
      contextLengthBuffer,
      this.context,
    ]);

    return hkdfLabelBuffer;
  }
}
