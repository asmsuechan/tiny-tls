import net from "net";
import { ContentType, TlsRecord } from "./models/tls_record";
import { TlsHandshakeProcessor } from "./tls_handshake_processor";

let handshakeProcessor: TlsHandshakeProcessor = new TlsHandshakeProcessor();

const server = net.createServer((socket) => {
  console.log("クライアントが接続しました。");

  socket.on("data", (data) => {
    console.log(`クライアントからのメッセージ: ${data.toString("hex")}`);

    // NOTE: 1703030012...1703030020...みたいに、複数のApplicationDataがいっぺんに届くこともある
    // tlsRecordではなく、tlsRecordsにして1レコードずつ処理を進めるべき。
    const tlsRecords: TlsRecord[] = [];
    let offset = 0;

    while (offset < data.length) {
      if (offset + 5 > data.length) {
        console.error("不完全なTLSレコードヘッダーを検出しました。");
        break;
      }

      // 4バイト目と5バイト目がlength
      const length = data.readUInt16BE(offset + 3);
      const recordEnd = offset + 5 + length;

      if (recordEnd > data.length) {
        console.error("不完全なTLSレコードを検出しました。");
        break;
      }

      const recordData = data.slice(offset, recordEnd);
      const tlsRecord = TlsRecord.from(recordData);
      tlsRecords.push(tlsRecord);

      offset = recordEnd;
    }

    for (const tlsRecord of tlsRecords) {
      if (tlsRecord.contentType === ContentType.handshake) {
        handshakeProcessor.process(tlsRecord, socket);
      }
    }

    console.log("tlsRecords:", tlsRecords);
  });

  socket.on("end", () => {
    console.log("クライアントが切断しました。");
    handshakeProcessor = new TlsHandshakeProcessor();
  });

  socket.on("error", (err) => {
    console.error(`ソケットエラー: ${err}`);
    handshakeProcessor = new TlsHandshakeProcessor();
  });
});

server.listen(443, () => {
  console.log("サーバーがポート443で起動しました。");
});

server.on("error", (err) => {
  console.error(`サーバーエラー: ${err}`);
});
