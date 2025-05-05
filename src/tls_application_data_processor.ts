import { TlsRecord } from "./models/tls_record";
import { TlsCryptoService } from "./services/tls_crypto_service";

import net from "net";

export class TlsApplicationDataProcessor {
  private applicationDataRcvSequenceNumber: number;
  private clientApplicationTrafficSecret: Buffer;
  private clientApplicationWriteKey: Buffer;
  private clientApplicationWriteIv: Buffer;
  private masterSecret: Buffer;

  private applicationDataSequenceNumber: number = 0;

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

  sendData(socket: net.Socket, applicationTlsRecord: TlsRecord) {
    const tlsCryptoService = new TlsCryptoService();
    /* サーバーサイドのキーを求める */
    const serverApplicationTrafficSecret = tlsCryptoService.deriveSecret(
      this.masterSecret,
      "s ap traffic",
      this.handshakeHash
    );

    const serverApplicationWriteKey = tlsCryptoService.hkdfExpandLabel(
      Buffer.from(serverApplicationTrafficSecret),
      "key",
      Buffer.from([]),
      32
    );
    const serverApplicationWriteIv = tlsCryptoService.hkdfExpandLabel(
      Buffer.from(serverApplicationTrafficSecret),
      "iv",
      Buffer.from([]),
      12
    );

    socket.write(
      applicationTlsRecord.encrypt(
        this.applicationDataSequenceNumber,
        Buffer.from(serverApplicationWriteKey),
        Buffer.from(serverApplicationWriteIv)
      ),
      "hex"
    );
    this.applicationDataSequenceNumber += 1;
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
