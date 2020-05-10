package org.pcap4j.packet.tls.records.handshakes;

import org.pcap4j.util.ByteArrays;

public class BasicHandshakeRecordContent implements HandshakeRecordContent {

    /**
     * 0x0          - Content
     * 0x0 + length - End
     */

    private final byte[] content;

    public static BasicHandshakeRecordContent newInstance(byte[] rawData, int offset, int length) {
        if(length > 0) {
            ByteArrays.validateBounds(rawData, offset, length);
        }
        return new BasicHandshakeRecordContent(rawData, offset, length);
    }

    public BasicHandshakeRecordContent(byte[] rawData, int offset, int length) {
        content = new byte[length];
        if (length > 0) {
            System.arraycopy(rawData, offset, content, 0, length);
        }
    }

    public BasicHandshakeRecordContent(byte[] content) {
        this.content = content;
    }

    public byte[] getContent() {
        return content;
    }

    @Override
    public String toString() {
        return "    [" + content.length + " bytes]";
    }

    @Override
    public byte[] toByteArray() {
        return content;
    }
}
