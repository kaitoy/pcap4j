package org.pcap4j.packet.tls.records;

import org.pcap4j.packet.tls.records.handshakes.*;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.packet.namednumber.tls.HandshakeType;

import java.util.Arrays;

import static org.pcap4j.util.ByteArrays.BYTE_SIZE_IN_BYTES;

public class HandshakeRecord implements TlsRecord {

    /*
    0x0 - Handshake type
    0x1 - Handshake length
    0x4 - Handshake version
    0x6 - Handshake content
     */

    private static final int HANDSHAKE_TYPE_OFFSET = 0;
    private static final int LENGTH_OFFSET = HANDSHAKE_TYPE_OFFSET + BYTE_SIZE_IN_BYTES;
    private static final int CONTENT_OFFSET = LENGTH_OFFSET + 3;

    private HandshakeType handshakeType;
    private int handshakeLength;  // 3 bytes
    private HandshakeRecordContent content;

    public static HandshakeRecord newInstance(byte[] rawData, int offset, int length) {
        ByteArrays.validateBounds(rawData, offset, length);
        return new HandshakeRecord(rawData, offset, length);
    }

    private HandshakeRecord(byte[] rawData, int offset, int length) {
        this.handshakeType = HandshakeType.getInstance(ByteArrays.getByte(rawData, HANDSHAKE_TYPE_OFFSET + offset));

        if (handshakeType == HandshakeType.ENCRYPTED_HANDSHAKE_MESSAGE) {
            this.handshakeLength = length;
            this.content = BasicHandshakeRecordContent.newInstance(
                    rawData, offset, handshakeLength);
            return;
        }

        this.handshakeLength = ByteArrays.getThreeBytesInt(rawData, LENGTH_OFFSET + offset);

        if (handshakeType == HandshakeType.CLIENT_HELLO) {
            this.content = ClientHelloHandshakeRecordContent.newInstance(
                    rawData, offset + CONTENT_OFFSET, handshakeLength);
        } else if (handshakeType == HandshakeType.SERVER_HELLO) {
            this.content = ServerHelloHandshakeRecordContent.newInstance(
                    rawData, offset + CONTENT_OFFSET, handshakeLength);
        } else if (handshakeType == HandshakeType.CERTIFICATE) {
            this.content = CertificateHandshakeRecordContent.newInstance(
                    rawData, offset + CONTENT_OFFSET, handshakeLength);
        } else {
            this.content = BasicHandshakeRecordContent.newInstance(
                    rawData, offset + CONTENT_OFFSET, handshakeLength);
        }
    }

    public HandshakeType getHandshakeType() {
        return handshakeType;
    }

    public HandshakeRecordContent getContent() {
        return content;
    }

    @Override
    public String toString() {
        return "    Handshake length: " + handshakeLength + "\n" +
                "    Handshake type: " + handshakeType + "\n" +
                content.toString();
    }

    @Override
    public byte[] toByteArray() {
        return ByteArrays.concatenate(Arrays.asList(
                ByteArrays.toByteArray(handshakeType.value()),
                ByteArrays.toByteArray(handshakeLength),
                content.toByteArray()
        ));
    }
}
