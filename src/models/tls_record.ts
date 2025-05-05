import { TlsCryptoService } from "../services/tls_crypto_service";
import { Handshake } from "./handshake";

export enum ContentType {
  invalid = 0,
  changeCipherSpec = 20,
  alert = 21,
  handshake = 22,
  applicationData = 23,
}

enum ProtocolVersion {
  TLS_1_0 = 0x0301,
  TLS_1_1 = 0x0302,
  TLS_1_2 = 0x0303,
  TLS_1_3 = 0x0304,
}

// NOTE: TLSPlaintext or TLSCiphertextを表す
// データ構造的にはTLSPlaintextを表している
export class TlsRecord {
  // 5.1. Record Layer
  // 例 16 03 03 00 b6 .....
  constructor(
    public contentType: ContentType, // 1バイト
    public legacyRecordVersion: ProtocolVersion, // 2バイト
    public length: number, // 2バイト
    public fragment: Buffer | Handshake
  ) {}

  static from(data: Buffer) {
    const contentType = data.readUInt8(0);
    if (ContentType[contentType] === undefined) {
      throw new Error(`Invalid content type: ${contentType}`);
    }

    const version = data.readUInt16BE(1);
    if (ProtocolVersion[version] === undefined) {
      throw new Error(`Invalid version: ${version}`);
    }

    const length = data.readUInt16BE(3);

    const rest = data.slice(5);

    let fragment: Buffer | Handshake = rest;
    if (contentType === ContentType.handshake) {
      fragment = Handshake.from(rest);
    } else if (contentType === ContentType.applicationData) {
      // NOTE: 復号せずそのまま暗号化されたBufferを突っ込んでおく。decode関数で復号する。
      fragment = rest;
    }

    return new TlsRecord(contentType, version, length, fragment);
  }

  bytes() {
    const headerBuffer = Buffer.alloc(5);
    headerBuffer.writeUInt8(this.contentType, 0);
    headerBuffer.writeUInt16BE(this.legacyRecordVersion, 1);
    headerBuffer.writeUInt16BE(this.length, 3);

    if (Buffer.isBuffer(this.fragment)) {
      return Buffer.concat([headerBuffer, this.fragment]);
    } else {
      return Buffer.concat([headerBuffer, this.fragment.bytes()]);
    }
  }

  private generateNonce(sequenceNumber: Buffer, staticNonce: Buffer) {
    const paddedSequenceNumber = Buffer.alloc(12);
    sequenceNumber.copy(paddedSequenceNumber, 4); // シーケンス番号をオフセット4からコピー

    const nonce = Buffer.alloc(12);
    for (let i = 0; i < 12; i++) {
      nonce[i] = paddedSequenceNumber[i] ^ staticNonce[i];
    }

    return nonce;
  }

  private generateAad(data: Buffer, encryption: boolean) {
    const lengthBuffer = Buffer.alloc(2);
    // NOTE: 16は認証タグの長さ
    const adjustedLength = encryption ? 16 : 0;
    lengthBuffer.writeUInt16BE(data.length + adjustedLength, 0);

    const protocolVersionBuffer = Buffer.alloc(2);
    protocolVersionBuffer.writeUInt16BE(this.legacyRecordVersion, 0);

    return Buffer.concat([
      Buffer.from([ContentType.applicationData]), // 0x17 (23)
      protocolVersionBuffer, // 0x0303
      lengthBuffer,
    ]);
  }

  encrypt(sequenceNumber: number, writeKey: Buffer, writeIv: Buffer) {
    const service = new TlsCryptoService();
    const sequenceNumberBuffer = Buffer.alloc(8);
    sequenceNumberBuffer.writeBigUInt64BE(BigInt(sequenceNumber), 0);
    const staticNonce = writeIv;
    const nonce = this.generateNonce(sequenceNumberBuffer, staticNonce);

    const content = Buffer.isBuffer(this.fragment)
      ? this.fragment
      : this.fragment.bytes();
    // > content: The TLSPlaintext.fragment value, containing the byte encoding of a
    // > handshake or an alert message, or the raw bytes of the application's data to send.
    const tlsInnerPlaintext = new TlsInnerPlaintext(
      content,
      this.contentType,
      Buffer.alloc(0) // 0バイトのパディング
    );
    const plaintextBuffer = tlsInnerPlaintext.bytes();

    const aad = this.generateAad(plaintextBuffer, true);

    const encryptedData = service.aeadEncrypt(
      writeKey,
      nonce,
      aad,
      plaintextBuffer
    );

    const headerBuffer = Buffer.alloc(5);
    headerBuffer.writeUInt8(ContentType.applicationData, 0);
    headerBuffer.writeUInt16BE(this.legacyRecordVersion, 1);
    headerBuffer.writeUInt16BE(encryptedData.length, 3);

    return Buffer.concat([headerBuffer, encryptedData]);
  }

  decrypt(
    readSequenceNumber: bigint,
    clientWriteKey: Buffer,
    clientWriteIv: Buffer
  ) {
    // NOTE: Handshakeは復号しない
    if (!Buffer.isBuffer(this.fragment)) {
      throw new Error("Fragment must be a Buffer for decryption");
    }

    const encryptedData = this.fragment;
    const sequenceNumberBuffer = Buffer.alloc(8);
    sequenceNumberBuffer.writeBigUInt64BE(readSequenceNumber, 0);
    const nonce = this.generateNonce(sequenceNumberBuffer, clientWriteIv);
    const aad = this.generateAad(encryptedData, false);

    const tagLength = 16; // GCMは16バイトの認証タグを持つ

    const ciphertext = encryptedData.subarray(
      0,
      encryptedData.length - tagLength
    );
    const authTag = encryptedData.subarray(encryptedData.length - tagLength);
    const service = new TlsCryptoService();

    const decryptedData = service.aeadDecrypt(
      ciphertext,
      clientWriteKey,
      nonce,
      aad,
      authTag
    );
    return decryptedData;
  }
}

export class TlsInnerPlaintext {
  constructor(
    public content: Buffer,
    public contentType: ContentType,
    public zeros: Buffer
  ) {}

  // NOTE: lengthはTlsRecordのlengthと同じ
  static from(data: Buffer, length: number) {
    const content = data.slice(0, length);
    const contentType = data.readUInt8(length);
    const zeros = data.slice(length + 1);

    return new TlsInnerPlaintext(content, contentType, zeros);
  }

  bytes() {
    const contentTypeBuffer = Buffer.alloc(1);
    contentTypeBuffer.writeUInt8(this.contentType);

    return Buffer.concat([this.content, contentTypeBuffer, this.zeros]);
  }
}
