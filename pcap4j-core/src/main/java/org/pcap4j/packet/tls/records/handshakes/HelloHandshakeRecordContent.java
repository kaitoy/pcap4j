package org.pcap4j.packet.tls.records.handshakes;

import org.pcap4j.packet.tls.extensions.TlsExtension;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.packet.namednumber.tls.ExtensionType;
import org.pcap4j.packet.namednumber.tls.TlsVersion;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.pcap4j.util.ByteArrays.BYTE_SIZE_IN_BYTES;
import static org.pcap4j.util.ByteArrays.SHORT_SIZE_IN_BYTES;

public abstract class HelloHandshakeRecordContent implements HandshakeRecordContent {

    private static final int VERSION_OFFSET = 0;
    private static final int RANDOM_OFFSET = VERSION_OFFSET + SHORT_SIZE_IN_BYTES;
    private static final int SESSION_ID_LENGTH_OFFSET = RANDOM_OFFSET + 32;
    protected static final int SESSION_ID_OFFSET = SESSION_ID_LENGTH_OFFSET + BYTE_SIZE_IN_BYTES;

    protected TlsVersion version;
    protected byte[] random = new byte[32];
    protected byte sessionIdLength;
    protected byte[] sessionId;

    protected short extensionsLength;
    private List<TlsExtension> extensions;

    protected void readCommonPart(byte[] rawData, int offset) {
        this.version = TlsVersion.getInstance(ByteArrays.getShort(rawData, VERSION_OFFSET + offset));
        System.arraycopy(rawData, RANDOM_OFFSET + offset, random, 0, 32);
        this.sessionIdLength = ByteArrays.getByte(rawData, SESSION_ID_LENGTH_OFFSET + offset);
        this.sessionId = new byte[sessionIdLength];

        if (sessionIdLength != 0) {
            System.arraycopy(rawData, SESSION_ID_OFFSET + offset, sessionId, 0, sessionIdLength);
        }
    }

    protected void readExtensions(byte[] rawData, int offset, boolean client) {
        extensions = new ArrayList<>(extensionsLength);

        int cursor = offset;
        int extensionsEnd = cursor + extensionsLength;

        while (cursor < extensionsEnd) {
            ExtensionType extensionType = ExtensionType.getInstance(ByteArrays.getShort(rawData, cursor));
            cursor += SHORT_SIZE_IN_BYTES;
            short extensionLength = ByteArrays.getShort(rawData, cursor);
            cursor += SHORT_SIZE_IN_BYTES;

            extensions.add(TlsExtension.newInstance(extensionType, rawData, cursor, extensionLength, client));

            cursor += extensionLength;
        }
    }

    public TlsVersion getVersion() {
        return version;
    }

    public byte[] getRandom() {
        return random;
    }

    public byte[] getSessionId() {
        return sessionId;
    }

    public List<TlsExtension> getExtensions() {
        return extensions;
    }

    @Override
    public String toString() {
        return "    TLS version: " + version + "\n" +
                "    Random: " + ByteArrays.toHexString(random, "") + "\n" +
                "    Session id: " + (sessionIdLength > 0 ? ByteArrays.toHexString(sessionId, "") : "null") + "\n" +
                "    Extensions: " + extensions.toString();
    }

    protected byte[] commonPartToByteArray() {
        return ByteArrays.concatenate(Arrays.asList(
                ByteArrays.toByteArray(version.value()),
                random,
                ByteArrays.toByteArray(sessionIdLength),
                sessionId
        ));
    }

    protected byte[] extensionsToByteArray() {
        List<byte[]> list = new ArrayList<>();

        list.add(ByteArrays.toByteArray(extensionsLength));
        for (TlsExtension extension : extensions) {
            list.add(extension.toByteArray());
        }

        return ByteArrays.concatenate(list);
    }
}
