import { ClientHello } from "./client_hello";

// 4. Handshake Protocol
export enum HandshakeType {
  ClientHello = 1,
  ServerHello = 2,
  NewSessionTicket = 4,
  EndOfEarlyData = 5,
  EncryptedExtensions = 8,
  Certificate = 11,
  CertificateRequest = 13,
  CertificateVerify = 15,
  Finished = 20,
  KeyUpdate = 24,
  MessageHash = 254,
}

export class Handshake {
  constructor(
    public msgType: HandshakeType,
    public length: number,
    // NOTE: 受け入れる型にClientHelloを追加
    public body: Buffer | ClientHello
  ) {}

  static from(data: Buffer): Handshake {
    const msgType = data.readUInt8(0);
    if (HandshakeType[msgType] === undefined) {
      throw new Error(`Invalid handshake type: ${msgType}`);
    }

    const length = data.readUIntBE(1, 3); // 3バイトの長さフィールド

    const body = data.slice(4); // 4バイト目以降がボディ
    // 01 00 07 0e 03 03

    let parsedBody: Buffer | ClientHello = body;
    if (msgType === HandshakeType.ClientHello) {
      parsedBody = ClientHello.from(body);
    }

    return new Handshake(msgType, length, parsedBody);
  }

  bytes() {
    const headerBuffer = Buffer.alloc(4);
    headerBuffer.writeUInt8(this.msgType, 0);
    // 3バイトの長さフィールドを書き込む
    headerBuffer.writeUIntBE(this.length, 1, 3);

    if (Buffer.isBuffer(this.body)) {
      return Buffer.concat([headerBuffer, this.body]);
    }

    return Buffer.concat([headerBuffer, this.body.bytes()]);
  }
}
