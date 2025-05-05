import {
  Extension,
  ExtensionType,
  KeyShare,
  SupportedVersion,
} from "./extension";

enum ProtocolVersion {
  TLS_1_2 = 0x0303,
}

export class ClientHello {
  constructor(
    public protocolVersion: ProtocolVersion,
    public sessionId: Buffer,
    public random: Buffer,
    public cipherSuites: Buffer,
    // NOTE: ここの方をBufferからExtension[]に変更
    public extensions: Extension[],
    // NOTE: Transcript-Hashの導入時に使うため、全文を保持しておく
    public original: Buffer
  ) {}

  static from(data: Buffer) {
    const protocolVersion = data.readUInt16BE(0);
    if (ProtocolVersion[protocolVersion] === undefined) {
      throw new Error(`Invalid protocol version: ${protocolVersion}`);
    }

    const random = data.slice(2, 34);

    const sessionIdLength = data.readUInt8(34);
    const sessionId = data.slice(35, 35 + sessionIdLength);

    const cipherSuitesLengthStartIndex = 35 + sessionIdLength;
    const cipherSuitesLength = data.readUInt16BE(cipherSuitesLengthStartIndex);
    const cipherSuitesEndIndex =
      cipherSuitesLengthStartIndex + 2 + cipherSuitesLength;
    const cipherSuites = data.slice(
      cipherSuitesLengthStartIndex + 2,
      cipherSuitesEndIndex
    );

    // NOTE: compression method lengthとcompression methodもあるが、TLS1.3ではlengthは01でmethodはnullを表す00になる。
    // +2はcompression分の長さ
    const extensionsLengthStartIndex = cipherSuitesEndIndex + 2;

    const extensionsLength = data.readUInt16BE(extensionsLengthStartIndex);
    const extensionsStartIndex = extensionsLengthStartIndex + 2;
    const extensions = data.slice(
      extensionsStartIndex,
      extensionsStartIndex + extensionsLength
    );
    return new ClientHello(
      protocolVersion,
      sessionId,
      random,
      cipherSuites,
      this.parseExtensions(extensions),
      data
    );
  }

  bytes(): Buffer {
    return this.original;
  }

  private static parseExtensions(data: Buffer) {
    const extensions: Extension[] = [];
    let offset = 0;
    while (offset < data.length) {
      const extensionType = data
        .slice(offset, offset + 2)
        .readUInt16BE() as ExtensionType;
      const length = data.readUInt16BE(offset + 2);
      const extensionData = data.slice(offset + 4, offset + 4 + length);
      let parsedExtensionData;
      if (extensionType === ExtensionType.SupportedVersions) {
        parsedExtensionData = SupportedVersion.from(extensionData);
      } else if (extensionType === ExtensionType.KeyShare) {
        parsedExtensionData = KeyShare.from(extensionData);
      } else {
        // NOTE: 残りはBufferをそのまま保持する
        parsedExtensionData = extensionData;
      }
      // NOTE: typeとlengthは2バイトずつなので4バイト
      offset += 4 + length;
      const extension = new Extension(extensionType, parsedExtensionData);
      extensions.push(extension);
    }
    return extensions;
  }
}
