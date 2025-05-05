export enum ExtensionType {
  ServerName = 0x0000,
  PreSharedKey = 0x0029,
  SupportedVersions = 0x002b,
  KeyShare = 0x0033,
}

export class SupportedVersion {
  // NOTE: 0x0304
  constructor(public version: Buffer) {}

  static from(data: Buffer) {
    return new SupportedVersion(data);
  }

  bytes() {
    return this.version;
  }
}

export class KeyShare {
  // NOTE: ServerHelloの場合、KeyShareのlengthは不要
  constructor(public length: number, public entries: KeyShareEntry[]) {}

  static from(data: Buffer) {
    const length = data.readUInt16BE(0);

    const entries: KeyShareEntry[] = [];
    // NOTE: 最初の2バイトはlengthのため省く
    let offset = 2;

    while (offset < data.length) {
      const group = data.slice(offset, offset + 2);
      const entryLength = data.readUInt16BE(offset + 2);
      const entry = KeyShareEntry.from(
        data.slice(offset, offset + 4 + entryLength)
      );
      entries.push(entry);
      // NOTE: 4はgroup(2) + length(2)の長さ分
      // 残りのデータから今処理したKeyShareEntryの長さ分を削除
      offset += 4 + entryLength;
    }
    return new KeyShare(length, entries);
  }

  x2559Key() {
    // NOTE: x25519で固定する
    const entry = this.entries.find((entry) =>
      entry.group.equals(Buffer.from([0x00, 0x1d]))
    );
    return entry ? entry.keyExchange : null;
  }

  _bytes(): Buffer {
    const entryBuffers = this.entries.map((entry) => entry.bytes());
    const allEntries = Buffer.concat(entryBuffers);

    const lengthBuffer = Buffer.alloc(2);
    lengthBuffer.writeUInt16BE(allEntries.length, 0);
    return Buffer.concat([lengthBuffer, allEntries]);
  }
  bytes(): Buffer {
    const entryBuffers = this.entries.map((entry) => entry.bytes());
    return Buffer.concat(entryBuffers);
  }
}

export class KeyShareEntry {
  constructor(
    public group: Buffer,
    public length: number,
    public keyExchange: Buffer
  ) {}

  static from(data: Buffer) {
    // NOTE: 最初の2バイトがグループ
    const group = data.slice(0, 2);
    // NOTE: 次の2バイトがlength
    const length = data.readUInt16BE(2);
    // NOTE: 次のlengthバイトがkeyExchange
    const keyExchange = data.slice(4, 4 + length);

    return new this(group, length, keyExchange);
  }

  bytes(): Buffer {
    const lengthBuffer = Buffer.alloc(2);
    lengthBuffer.writeUInt16BE(this.keyExchange.length, 0);

    return Buffer.concat([this.group, lengthBuffer, this.keyExchange]);
  }
}

export class Extension {
  constructor(
    public extensionType: ExtensionType,
    public data: SupportedVersion | KeyShare | Buffer
  ) {}

  static from(data: Buffer) {
    const extensionType = data.slice(0, 2).readUInt16BE() as ExtensionType;
    const length = data.readUInt16BE(2);
    const rawExtensionData = data.slice(4, 4 + length);

    let extensionData;
    if (extensionType === ExtensionType.SupportedVersions) {
      extensionData = SupportedVersion.from(rawExtensionData);
    } else if (extensionType === ExtensionType.KeyShare) {
      extensionData = KeyShare.from(rawExtensionData);
    } else {
      throw new Error(`Invalid extension type: ${extensionType}`);
    }

    return new Extension(extensionType, extensionData);
  }

  bytes() {
    const extensionTypeBuffer = Buffer.from([0x00, this.extensionType]);

    let dataBuffer: Buffer;
    if (Buffer.isBuffer(this.data)) {
      dataBuffer = this.data;
    } else if (
      this.data instanceof SupportedVersion ||
      this.data instanceof KeyShare
    ) {
      dataBuffer = this.data.bytes();
    } else {
      throw new Error("Unsupported data type in Extension");
    }

    const lengthBuffer = Buffer.alloc(2);
    lengthBuffer.writeUInt16BE(dataBuffer.length, 0);

    return Buffer.concat([extensionTypeBuffer, lengthBuffer, dataBuffer]);
  }
}
