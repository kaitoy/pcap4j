package org.pcap4j.packet.tls.records.handshakes;

import org.pcap4j.packet.namednumber.tls.TlsVersion;
import org.pcap4j.packet.tls.extensions.TlsExtension;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.packet.namednumber.tls.CipherSuite;
import org.pcap4j.packet.namednumber.tls.CompressionMethod;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.pcap4j.util.ByteArrays.BYTE_SIZE_IN_BYTES;
import static org.pcap4j.util.ByteArrays.SHORT_SIZE_IN_BYTES;

public class ClientHelloHandshakeRecordContent extends HelloHandshakeRecordContent {

    /*
    0x0                  - TLS version
    0x2                  - Client random
    0x22                 - Session id length (sidl)
    0x23                 - Session id
    0x23+sidl            - Cipher suites length (csl)
    0x25+sidl            - Cipher suite 1..(csl/2)
    0x25+sidl+csl        - Compression methods length (cml)
    0x26+sidl+csl        - Compression method 1..cml
    0x26+sidl+csl+cml    - Extensions Length (el)
    0x28+sidl+csl+cml    - Extension 1..N
    0x28+sidl+csl+cml+el - End
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

    private final short cipherSuitesLength;
    private final List<CipherSuite> cipherSuites;
    private final byte compressionMethodsLength;
    private final List<CompressionMethod> compressionMethods;

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

    public ClientHelloHandshakeRecordContent(TlsVersion version, byte[] random, byte[] sessionId,
                                             short extensionsLength, List<TlsExtension> extensions,
                                             List<CipherSuite> cipherSuites,
                                             List<CompressionMethod> compressionMethods) {
        super(version, random, sessionId, extensionsLength, extensions);
        this.cipherSuitesLength = (short) (cipherSuites.size() * SHORT_SIZE_IN_BYTES);
        this.cipherSuites = cipherSuites;
        this.compressionMethodsLength = (byte) compressionMethods.size();
        this.compressionMethods = compressionMethods;
    }

    public short getCipherSuitesLength() {
        return cipherSuitesLength;
    }

    public List<CipherSuite> getCipherSuites() {
        return cipherSuites;
    }

    public byte getCompressionMethodsLength() {
        return compressionMethodsLength;
    }

    public List<CompressionMethod> getCompressionMethods() {
        return compressionMethods;
    }

    @Override
    public String toString() {
        return super.toString() + "\n" +
                "    Cipher suites: " + cipherSuites.toString() + "\n" +
                "    Compression methods: " + compressionMethods.toString();
    }

    @Override
    public byte[] toByteArray() {
        return ByteArrays.concatenate(Arrays.asList(
                commonPartToByteArray(),
                ByteArrays.toByteArray(cipherSuitesLength),
                cipherSuitesToByteArray(),
                ByteArrays.toByteArray(compressionMethodsLength),
                compressionMethodsToByteArray(),
                extensionsToByteArray()
        ));
    }

    private byte[] cipherSuitesToByteArray() {
        List<byte[]> list = new ArrayList<>();

        for (CipherSuite suite : cipherSuites) {
            list.add(ByteArrays.toByteArray(suite.value()));
        }

        return ByteArrays.concatenate(list);
    }

    private byte[] compressionMethodsToByteArray() {
        byte[] array = new byte[compressionMethods.size()];

        for (int i = 0; i < compressionMethods.size(); i++) {
            array[i] = compressionMethods.get(i).value();
        }

        return array;
    }

}
