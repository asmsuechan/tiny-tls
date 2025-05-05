export class EncryptedExtensions {
  constructor(public extensions: Buffer) {}

  static from(data: Buffer) {
    const extensions = data;
    return new EncryptedExtensions(extensions);
  }

  bytes() {
    const lengthBuffer = Buffer.alloc(2);
    lengthBuffer.writeUInt16BE(this.extensions.length, 0);
    return Buffer.concat([lengthBuffer, this.extensions]);
  }
}
