import { ClientHello } from "./models/client_hello";
import { Extension, ExtensionType, KeyShare } from "./models/extension";
import { Handshake, HandshakeType } from "./models/handshake";
import { ContentType, TlsRecord } from "./models/tls_record";
import net from "net";
import fs from "fs";
import { KeyService } from "./services/key_service";
import { ServerHello } from "./models/server_hello";
import { TlsCryptoService } from "./services/tls_crypto_service";
import { EncryptedExtensions } from "./models/encrypted_extentions";
import { Certificate, CertificateEntry } from "./models/certificate";
import { CertificateVerify } from "./models/certificate_verify";
import { Finished } from "./models/finished";

export class TlsHandshakeProcessor {
  private tlsCryptoService: TlsCryptoService = new TlsCryptoService();
  public handshakeSecret: Buffer | null = null;
  private sequenceNumber: number = 0;
  public handshakeHash: Buffer | null = null;

  process(tlsRecord: TlsRecord, socket: net.Socket) {
    console.log("ハンドシェイク処理を開始します。");

    // HandshakeかつClientHelloであることを確認
    if (
      !(
        tlsRecord.fragment instanceof Handshake &&
        tlsRecord.fragment.body instanceof ClientHello
      )
    ) {
      return null;
    }

    const clientHello = tlsRecord.fragment.body;

    const clientKeyShare = clientHello.extensions.find(
      (ext: Extension) => ext.extensionType === ExtensionType.KeyShare
    );
    if (clientKeyShare === undefined) {
      throw new Error("KeyShare extension not found in ClientHello");
    }
    const rawClientPubKey = (clientKeyShare.data as KeyShare).x2559Key();
    if (rawClientPubKey == null) {
      throw new Error("x25519 key not found in KeyShare extension");
    }

    console.log("x25519 key:", rawClientPubKey);

    const keyPair = new KeyService().generateX25519KeyPair();

    /* ServerHello */
    const serverHello = ServerHello.from(clientHello.sessionId, keyPair);
    const serverHelloBuffer = serverHello.bytes();
    const serverHelloHandshake = new Handshake(
      HandshakeType.ServerHello,
      serverHelloBuffer.length,
      serverHelloBuffer
    );
    const serverHelloTlsRecord = new TlsRecord(
      ContentType.handshake,
      0x0303,
      serverHelloHandshake.bytes().length,
      serverHelloHandshake
    );
    socket.write(serverHelloTlsRecord.bytes());
    /* ServerHello */

    const earlySecret = this.tlsCryptoService.hkdfExtract(
      Buffer.alloc(this.tlsCryptoService.getHashLength()),
      Buffer.alloc(this.tlsCryptoService.getHashLength())
    );

    const derivedSecret = this.tlsCryptoService.deriveSecret(
      earlySecret,
      "derived",
      Buffer.from([])
    );

    const clientPubKey = new KeyService().encodeX25519PublicKeyToDer(
      rawClientPubKey
    );
    const serverPrivateKey = keyPair.privateKey;
    const sharedSecret = new KeyService().generateCommonSecret(
      serverPrivateKey,
      clientPubKey
    );

    this.handshakeSecret = this.tlsCryptoService.hkdfExtract(
      derivedSecret,
      sharedSecret
    );

    const clientHelloPayload = tlsRecord.fragment.bytes();
    const serverHelloPayload = serverHelloHandshake.bytes();
    const serverHandshakeMessages = Buffer.concat([
      clientHelloPayload,
      serverHelloPayload,
    ]);

    const serverHandshakeTrafficSecret = this.tlsCryptoService.deriveSecret(
      this.handshakeSecret,
      "s hs traffic",
      serverHandshakeMessages
    );

    const serverWriteKey = this.tlsCryptoService.hkdfExpandLabel(
      Buffer.from(serverHandshakeTrafficSecret),
      "key",
      Buffer.from([]),
      32
    );

    const serverWriteIv = this.tlsCryptoService.hkdfExpandLabel(
      Buffer.from(serverHandshakeTrafficSecret),
      "iv",
      Buffer.from([]),
      12
    );

    /* EncryptedExtensions */
    const encryptedExtensions = new EncryptedExtensions(Buffer.from([]));
    const encryptedExtensionsBuffer = encryptedExtensions.bytes();
    const encryptedExtensionHandshake = new Handshake(
      HandshakeType.EncryptedExtensions,
      encryptedExtensionsBuffer.length,
      encryptedExtensionsBuffer
    );
    const encryptedExtensionTlsRecord = new TlsRecord(
      ContentType.handshake,
      0x0303,
      encryptedExtensionHandshake.bytes().length,
      encryptedExtensionHandshake
    );
    socket.write(
      encryptedExtensionTlsRecord.encrypt(
        this.sequenceNumber,
        Buffer.from(serverWriteKey),
        Buffer.from(serverWriteIv)
      )
    );
    console.log("Wrote EncryptedExtension!");
    this.sequenceNumber += 1;

    /* Certificate */
    const certificatePem = fs.readFileSync("server.crt", "utf8");
    const entry = new CertificateEntry(certificatePem);
    const certificate = Certificate.from([entry]);
    const certificateBuffer = certificate.bytes();
    const certificateHandshake = new Handshake(
      HandshakeType.Certificate,
      certificateBuffer.length,
      certificateBuffer
    );
    const certificateTlsRecord = new TlsRecord(
      ContentType.handshake,
      0x0303,
      certificateHandshake.bytes().length,
      certificateHandshake
    );
    socket.write(
      certificateTlsRecord.encrypt(
        this.sequenceNumber,
        Buffer.from(serverWriteKey),
        Buffer.from(serverWriteIv)
      )
    );
    console.log("Wrote Certificate!");
    this.sequenceNumber += 1;
    /* Certificate */

    /* CertificateVerify */
    const signTargetContent = this.tlsCryptoService.transcriptHash(
      Buffer.concat([
        clientHelloPayload,
        serverHelloPayload,
        encryptedExtensionHandshake.bytes(),
        certificateHandshake.bytes(),
      ])
    );
    const privateKeyStr = fs.readFileSync("server.key", "utf8");
    const certificateVerify = CertificateVerify.from(
      signTargetContent,
      privateKeyStr
    );
    const certificateVerifyBuffer = certificateVerify.bytes();
    const certificateVerifyHandshake = new Handshake(
      HandshakeType.CertificateVerify,
      certificateVerifyBuffer.length,
      certificateVerifyBuffer
    );
    const certificateVerifyTlsRecord = new TlsRecord(
      ContentType.handshake,
      0x0303,
      certificateVerifyHandshake.bytes().length,
      certificateVerifyHandshake
    );
    socket.write(
      certificateVerifyTlsRecord.encrypt(
        this.sequenceNumber,
        Buffer.from(serverWriteKey),
        Buffer.from(serverWriteIv)
      )
    );
    console.log("Wrote CertificateVerify!");
    this.sequenceNumber += 1;
    /* CertificateVerify */

    /* Finished */
    const encryptedExtensionPayload = encryptedExtensionHandshake.bytes();
    const certificatePayload = certificateHandshake.bytes();
    const certificateVerifyPayload = certificateVerifyHandshake.bytes();
    const handshakeMsgs = Buffer.concat([
      clientHelloPayload,
      serverHelloPayload,
      encryptedExtensionPayload,
      certificatePayload,
      certificateVerifyPayload,
    ]);

    const finished = Finished.from(serverHandshakeTrafficSecret, handshakeMsgs);
    const finishedBuffer = finished.bytes();
    const finishedHandshake = new Handshake(
      HandshakeType.Finished,
      finishedBuffer.length,
      finishedBuffer
    );
    const finishedTlsRecord = new TlsRecord(
      ContentType.handshake,
      0x0303,
      finishedHandshake.bytes().length,
      finishedHandshake
    );
    socket.write(
      finishedTlsRecord.encrypt(
        this.sequenceNumber,
        Buffer.from(serverWriteKey),
        Buffer.from(serverWriteIv)
      )
    );
    console.log("Wrote Finished!");
    this.sequenceNumber += 1;
    /* Finished */

    // NOTE: 最後に全てのハンドシェイクをまとめたデータをprocessで返すようにする
    const finishedHandshakePayload = finishedHandshake.bytes();
    const handshakeWithFinishMsgs = Buffer.concat([
      clientHelloPayload,
      serverHelloPayload,
      encryptedExtensionPayload,
      certificatePayload,
      certificateVerifyPayload,
      finishedHandshakePayload,
    ]);
    this.handshakeHash = handshakeWithFinishMsgs;
  }
}
