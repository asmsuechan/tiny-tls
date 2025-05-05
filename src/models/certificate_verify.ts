import crypto from "crypto";

export class CertificateVerify {
  /* RSASSA-PKCS1-v1_5 algorithms */
  // rsa_pkcs1_sha256(0x0401),

  // > In addition, the signature algorithm MUST be compatible with the key in the
  // > sender's end-entity certificate. RSA signatures MUST use an RSASSA-PSS algorithm,
  // > regardless of whether RSASSA-PKCS1-v1_5 algorithms appear in "signature_algorithms".
  // > The SHA-1 algorithm MUST NOT be used in any signatures of CertificateVerify messages.

  /* RSASSA-PSS algorithms with public key OID rsaEncryption */
  // rsa_pss_rsae_sha256(0x0804),
  public algorithm = Buffer.from([0x08, 0x04]);

  constructor(public signature: Buffer) {}

  // NOTE: transcriptHashは次で導出されたもの
  // Transcript-Hash(Handshake Context, Certificate)
  static from(transcriptHash: Buffer, privateKeyPem: string) {
    // NOTE: 署名の計算に必要なデータは下記の通り
    // > The digital signature is then computed over the concatenation of:
    // > - A string that consists of octet 32 (0x20) repeated 64 times
    // > - The context string
    // > - A single 0 byte which serves as the separator
    // > - The content to be signed

    const repeatedOctet = Buffer.alloc(64, 0x20);
    // The context stringは下記を表す
    // > The context string for a server signature is "TLS 1.3, server CertificateVerify".
    const contextString = Buffer.from("TLS 1.3, server CertificateVerify");
    const single0Byte = Buffer.from([0x00]);

    const signTarget = Buffer.concat([
      repeatedOctet,
      contextString,
      single0Byte,
      transcriptHash,
    ]);

    const privateKey = crypto.createPrivateKey(privateKeyPem);

    const signature = crypto.sign("RSA-SHA256", signTarget, {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: 32, // SHA-256 の場合 32 バイト
    });

    return new this(signature);
  }

  bytes(): Buffer {
    const signatureLength = Buffer.alloc(2);
    signatureLength.writeUInt16BE(this.signature.length, 0);
    return Buffer.concat([this.algorithm, signatureLength, this.signature]);
  }
}
