package org.pcap4j.packet.tls.records.handshakes;

import org.pcap4j.util.ByteArrays;
import org.pcap4j.packet.namednumber.tls.CipherSuite;
import org.pcap4j.packet.namednumber.tls.CompressionMethod;

import static org.pcap4j.util.ByteArrays.BYTE_SIZE_IN_BYTES;
import static org.pcap4j.util.ByteArrays.SHORT_SIZE_IN_BYTES;

public class ServerHelloHandshakeRecordContent extends HelloHandshakeRecordContent {

    /*
    0x0          - Server random
    0x20         - Session id length (sidl)
    0x21         - Session id
    0x21+si      - Cipher suite
    0x23+sidl    - Compression method
    0x24+sidl    - Extensions Length (el)
    0x26+sidl    - Extension 1..N
    0x26+sidl+el - End
     */

    private static final int CIPHER_SUITE_OFFSET = HelloHandshakeRecordContent.SESSION_ID_OFFSET;  // + sessionIdLength
    private static final int COMPRESSION_METHOD_OFFSET = CIPHER_SUITE_OFFSET + SHORT_SIZE_IN_BYTES;  // + sessionIdLength
    private static final int EXTENSIONS_LENGTH_OFFSET = COMPRESSION_METHOD_OFFSET + BYTE_SIZE_IN_BYTES;  // + sessionIdLength
    private static final int EXTENSIONS_OFFSET = EXTENSIONS_LENGTH_OFFSET + SHORT_SIZE_IN_BYTES;  // + sessionIdLength

    private CipherSuite cipherSuite;
    private CompressionMethod compressionMethod;

    public static ServerHelloHandshakeRecordContent newInstance(byte[] rawData, int offset, int length) {
        ByteArrays.validateBounds(rawData, offset, length);
        return new ServerHelloHandshakeRecordContent(rawData, offset);
    }

    public ServerHelloHandshakeRecordContent(byte[] rawData, int offset) {
        readCommonPart(rawData, offset);

        this.cipherSuite = CipherSuite.getInstance(ByteArrays.getShort(rawData,
                CIPHER_SUITE_OFFSET + sessionIdLength + offset));
        this.compressionMethod = CompressionMethod.getInstance(ByteArrays.getByte(rawData,
                COMPRESSION_METHOD_OFFSET + sessionIdLength + offset));

        this.extensionsLength = ByteArrays.getShort(rawData,
                EXTENSIONS_LENGTH_OFFSET + sessionIdLength + offset);
        readExtensions(rawData, EXTENSIONS_OFFSET + sessionIdLength + offset, false);
    }

    public CipherSuite getCipherSuite() {
        return cipherSuite;
    }

    public CompressionMethod getCompressionMethod() {
        return compressionMethod;
    }

    @Override
    public String toString() {
        return super.toString() + "\n" +
                "    Cipher suite: " + cipherSuite.toString() + "\n" +
                "    Compression method: " + compressionMethod.toString();
    }

}
