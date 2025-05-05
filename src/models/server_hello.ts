import { KeyPair, KeyService } from "../services/key_service";

import crypto from "crypto";
import {
  Extension,
  ExtensionType,
  KeyShare,
  KeyShareEntry,
  SupportedVersion,
} from "./extension";

enum ProtocolVersion {
  TLS_1_2 = 0x0303,
}

export class ServerHello {
  constructor(
    public protocolVersion: ProtocolVersion,
    public random: Buffer,
    public sessionIdEcho: Buffer,
    public cipherSuite: number,
    public compressionMethod: Buffer,
    public extensionLength: Buffer,
    public extensions: Buffer
  ) {}

  static from(clientSessionId: Buffer, keyPair: KeyPair) {
    const protocolVersion = ProtocolVersion.TLS_1_2;
    // NOTE: randomはgmt timestamp (4バイト) + 28バイトのランダムな値
    const gmtTimestampSeconds = Math.floor(Date.now() / 1000);
    const buffer = Buffer.alloc(4);
    buffer.writeInt32BE(gmtTimestampSeconds, 0);
    const random = Buffer.concat([buffer, crypto.randomBytes(28)]);

    // NOTE: B.4. Cipher Suites参照
    const cipherSuite = 0x1302; // TLS_AES_256_GCM_SHA384
    const compressionMethod = Buffer.from([0x00]); // nullで固定

    const supportedVersions = new Extension(
      ExtensionType.SupportedVersions,
      new SupportedVersion(Buffer.from([0x03, 0x04])) // 0304
    );

    const rawKey = new KeyService().extractRawKeyFromDerFormat(
      keyPair.publicKey
    );
    const keyShareEntry = new KeyShareEntry(
      Buffer.from([0x00, 0x1d]),
      32,
      Buffer.from(rawKey, "hex")
    );

    const keyShare = new Extension(
      ExtensionType.KeyShare,
      new KeyShare(
        // NOTE: x25519の公開鍵(key_share_entry) 32バイト + key_shareを表すtype (0033) の2バイト
        34,
        [keyShareEntry]
      )
    );

    const extensions = Buffer.concat([
      supportedVersions.bytes(),
      keyShare.bytes(),
    ]);

    const extensionLength = Buffer.alloc(2);
    extensionLength.writeUInt16BE(extensions.length, 0);

    return new ServerHello(
      protocolVersion,
      random,
      clientSessionId,
      cipherSuite,
      compressionMethod,
      extensionLength,
      extensions
    );
  }

  bytes() {
    const protocolVersionBuffer = Buffer.alloc(2);
    protocolVersionBuffer.writeUInt16BE(this.protocolVersion, 0);

    // session id length 32 (0x20) で固定
    const sessionIdLengthBuffer = Buffer.from([0x20]);

    const cipherSuiteBuffer = Buffer.alloc(2);
    cipherSuiteBuffer.writeUInt16BE(this.cipherSuite, 0);

    return Buffer.concat([
      protocolVersionBuffer,
      this.random,
      sessionIdLengthBuffer,
      this.sessionIdEcho,
      cipherSuiteBuffer,
      this.compressionMethod,
      this.extensionLength,
      this.extensions,
    ]);
  }
}
