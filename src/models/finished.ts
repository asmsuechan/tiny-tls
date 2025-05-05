import crypto from "crypto";
import { TlsCryptoService } from "../services/tls_crypto_service";

export class Finished {
  constructor(public verifyData: Buffer) {}

  static fromPlaintext(data: Buffer) {
    // 最初の32バイト（SHA-256の場合）または48バイト（SHA-384の場合）を取得
    return new Finished(data);
  }

  static from(secret: Buffer, handshakeMessages: Buffer) {
    // NOTE: serverAppTrafficSecret
    // finished_key =
    //   HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
    // verify_data =
    //   HMAC(finished_key,
    //     Transcript-Hash(Handshake Context,
    //                     Certificate*, CertificateVerify*))
    // BaseKeyはserver_handshake_traffic_secre (4.4より)
    const service = new TlsCryptoService();
    const finishedKey = service.hkdfExpandLabel(
      secret,
      "finished",
      Buffer.alloc(0),
      service.getHashLength()
    );
    const transcriptHash = service.transcriptHash(handshakeMessages);
    const hmac = crypto.createHmac("sha384", finishedKey);
    hmac.update(transcriptHash);
    const verifyData = hmac.digest();

    return new this(verifyData);
  }

  bytes(): Buffer {
    return this.verifyData;
  }

  // finishedKey: HKDF-Expand-Labelの結果 (calculateHkdfExpandLabel()関数の実行結果)
  // handshakeHash: Transcript-Hash(Handshake Context, Certificate*, CertificateVerify*))
  static generateVerifyData(finishedKey: Buffer, handshakeHash: Buffer) {
    const hmac = crypto.createHmac("sha384", finishedKey);
    hmac.update(handshakeHash);
    return hmac.digest();
  }
}
