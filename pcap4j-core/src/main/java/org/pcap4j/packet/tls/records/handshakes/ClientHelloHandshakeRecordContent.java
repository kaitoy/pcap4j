package org.pcap4j.packet.tls.records.handshakes;

import org.pcap4j.util.ByteArrays;
import org.pcap4j.packet.namednumber.tls.CipherSuite;
import org.pcap4j.packet.namednumber.tls.CompressionMethod;

import java.util.ArrayList;
import java.util.List;

import static org.pcap4j.util.ByteArrays.BYTE_SIZE_IN_BYTES;
import static org.pcap4j.util.ByteArrays.SHORT_SIZE_IN_BYTES;

public class ClientHelloHandshakeRecordContent extends HelloHandshakeRecordContent {

    /*
    0x0                  - Client random
    0x20                 - Session id length (sidl)
    0x21                 - Session id
    0x21+sidl            - Cipher suites length (csl)
    0x23+sidl            - Cipher suite 1..(csl/2)
    0x23+sidl+csl        - Compression methods length (cml)
    0x24+sidl+csl        - Compression method 1..cml
    0x24+sidl+csl+cml    - Extensions Length (el)
    0x26+sidl+csl+cml    - Extension 1..N
    0x26+sidl+csl+cml+el - End
     */

    private static final int CIPHER_SUITES_LENGTH_OFFSET = HelloHandshakeRecordContent.SESSION_ID_OFFSET;  // + sessionIdLength
    private static final int CIPHER_SUITE_OFFSET =
            CIPHER_SUITES_LENGTH_OFFSET + SHORT_SIZE_IN_BYTES; // + sessionIdLength + SHORT_SIZE_IN_BYTES*i
    private static final int COMPRESSION_METHODS_LENGTH_OFFSET = CIPHER_SUITE_OFFSET; // + sessionIdLength + cipherSuitesLength
    private static final int COMPRESSION_METHOD_OFFSET =
            COMPRESSION_METHODS_LENGTH_OFFSET + BYTE_SIZE_IN_BYTES; // + sessionIdLength + cipherSuitesLength + BYTE_SIZE_IN_BYTES*i
    private static final int EXTENSIONS_LENGTH_OFFSET =
            COMPRESSION_METHOD_OFFSET; // + sessionIdLength + cipherSuitesLength + compressionMethodsLength
    private static final int EXTENSIONS_OFFSET = COMPRESSION_METHOD_OFFSET + SHORT_SIZE_IN_BYTES;

    private short cipherSuitesLength;
    private List<CipherSuite> cipherSuites;
    private byte compressionMethodsLength;
    private List<CompressionMethod> compressionMethods;

    public static ClientHelloHandshakeRecordContent newInstance(byte[] rawData, int offset, int length) {
        ByteArrays.validateBounds(rawData, offset, length);
        return new ClientHelloHandshakeRecordContent(rawData, offset);
    }

    private ClientHelloHandshakeRecordContent(byte[] rawData, int offset) {
        readCommonPart(rawData, offset);

        this.cipherSuitesLength = ByteArrays.getShort(rawData, CIPHER_SUITES_LENGTH_OFFSET + sessionIdLength + offset);
        int cipherSuitesAmount = cipherSuitesLength / SHORT_SIZE_IN_BYTES;
        this.cipherSuites = new ArrayList<>(cipherSuitesAmount);

        for (int i = 0; i < cipherSuitesAmount; i++) {
            this.cipherSuites.add(CipherSuite.getInstance(ByteArrays.getShort(rawData,
                    CIPHER_SUITE_OFFSET + SHORT_SIZE_IN_BYTES * i + sessionIdLength + offset)));
        }

        this.compressionMethodsLength = ByteArrays.getByte(rawData,
                COMPRESSION_METHODS_LENGTH_OFFSET + cipherSuitesLength + sessionIdLength + offset);
        this.compressionMethods = new ArrayList<>(compressionMethodsLength);

        for (byte i = 0; i < compressionMethodsLength; i++) {
            this.compressionMethods.add(CompressionMethod.getInstance(ByteArrays.getByte(rawData,
                    COMPRESSION_METHOD_OFFSET + BYTE_SIZE_IN_BYTES * i + sessionIdLength + cipherSuitesLength + offset)));
        }

        this.extensionsLength = ByteArrays.getShort(rawData,
                EXTENSIONS_LENGTH_OFFSET + compressionMethodsLength + sessionIdLength + cipherSuitesLength + offset);

        readExtensions(rawData, EXTENSIONS_OFFSET + compressionMethodsLength +
                sessionIdLength + cipherSuitesLength + offset, true);
    }

    @Override
    public String toString() {
        return super.toString() + "\n" +
                "    Cipher suites: " + cipherSuites.toString() + "\n" +
                "    Compression methods: " + compressionMethods.toString();
    }
}
