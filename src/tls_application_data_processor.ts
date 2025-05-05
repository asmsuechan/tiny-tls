import { TlsRecord } from "./models/tls_record";
import { TlsCryptoService } from "./services/tls_crypto_service";

export class TlsApplicationDataProcessor {
  private applicationDataRcvSequenceNumber: number;
  private clientApplicationTrafficSecret: Buffer;
  private clientApplicationWriteKey: Buffer;
  private clientApplicationWriteIv: Buffer;
  private masterSecret: Buffer;

  public handshakeFinished: boolean;

  constructor(
    handshakeSecret: Buffer,
    private handshakeHash: Buffer,
    handshakeFinished: boolean
  ) {
    this.applicationDataRcvSequenceNumber = 0;
    this.handshakeFinished = handshakeFinished;

    const tlsCryptoService = new TlsCryptoService();

    const derivedSecret = tlsCryptoService.deriveSecret(
      handshakeSecret,
      "derived",
      Buffer.from([])
    );
    this.masterSecret = tlsCryptoService.hkdfExtract(
      derivedSecret,
      Buffer.alloc(tlsCryptoService.getHashLength())
    );

    /* クライアントのキーを求める */
    this.clientApplicationTrafficSecret = tlsCryptoService.deriveSecret(
      this.masterSecret,
      "c ap traffic",
      handshakeHash
    );
    console.log(
      "clientApplicationTrafficSecret: ",
      this.clientApplicationTrafficSecret.toString("hex")
    );
    this.clientApplicationWriteKey = tlsCryptoService.hkdfExpandLabel(
      this.clientApplicationTrafficSecret,
      "key",
      Buffer.from([]),
      32
    );
    this.clientApplicationWriteIv = tlsCryptoService.hkdfExpandLabel(
      this.clientApplicationTrafficSecret,
      "iv",
      Buffer.from([]),
      12
    );
  }

  process(tlsRecord: TlsRecord) {
    console.log("アプリケーションデータを処理します。");
    const decodedData = this.decodeApplicationData(tlsRecord);
    console.log("decodedData:", decodedData?.toString());
    if (decodedData) {
      this.applicationDataRcvSequenceNumber++;
    }

    return decodedData;
  }

  private decodeApplicationData(tlsRecord: TlsRecord) {
    if (this.handshakeFinished) {
      return tlsRecord.decrypt(
        BigInt(this.applicationDataRcvSequenceNumber),
        this.clientApplicationWriteKey,
        this.clientApplicationWriteIv
      );
    } else {
      console.log("Handshake is not finished yet.");
    }
  }
}
