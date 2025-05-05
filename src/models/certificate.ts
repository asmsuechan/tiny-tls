export class CertificateEntry {
  // NOTE: X.509形式のみ対応
  constructor(public certStr: string) {}

  pemToDer() {
    const lines = this.certStr.split("\n");
    const base64Encoded = lines
      .filter((line) => !line.startsWith("-----"))
      .join("");
    return Buffer.from(base64Encoded, "base64");
  }

  bytes() {
    // NOTE: X.509証明書タイプがネゴシエートされた場合、各CertificateEntryにはDERエンコードされたX.509証明書が含まれる
    const derCert = this.pemToDer();
    const certLength = derCert.length;
    const bufferCertLength = Buffer.alloc(3);
    bufferCertLength.writeUIntBE(certLength, 0, 3);

    const bufferCert = Buffer.from(derCert);

    // NOTE: extensionは空で固定
    const extensionLength = Buffer.alloc(2);

    return Buffer.concat([bufferCert, extensionLength]);
  }
}

export class Certificate {
  // certificate_request_contextは長さ0で固定
  constructor(public certificateList: CertificateEntry[]) {}

  static from(certificateList: CertificateEntry[]) {
    return new Certificate(certificateList);
  }

  bytes() {
    const certificateBuffers = this.certificateList.map((entry) => {
      const derCert = entry.pemToDer();
      const certLength = derCert.length;

      // 証明書の長さを3バイトで表現
      const certLengthBuffer = Buffer.alloc(3);
      certLengthBuffer.writeUIntBE(certLength, 0, 3);

      return Buffer.concat([certLengthBuffer, entry.bytes()]);
    });

    const certificatesBuffer = Buffer.concat(certificateBuffers);

    // 証明書リスト全体の長さを3バイトで表現
    const certificatesLengthBuffer = Buffer.alloc(3);
    certificatesLengthBuffer.writeUIntBE(certificatesBuffer.length, 0, 3);

    // Certificate Request Context Lengthは0で固定
    const contextLengthBuffer = Buffer.from([0x00]);

    return Buffer.concat([
      contextLengthBuffer,
      certificatesLengthBuffer,
      certificatesBuffer,
    ]);
  }
}
