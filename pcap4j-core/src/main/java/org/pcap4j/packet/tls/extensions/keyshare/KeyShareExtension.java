package org.pcap4j.packet.tls.extensions.keyshare;

import org.pcap4j.packet.tls.extensions.TlsExtension;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.packet.namednumber.tls.ExtensionType;

import java.util.ArrayList;
import java.util.List;

public abstract class KeyShareExtension extends TlsExtension {

    private final List<KeyShareEntry> entries = new ArrayList<>();

    public static KeyShareExtension newInstance(ExtensionType type, byte[] rawData, int offset,
                                                short extensionLength, boolean client) {
        ByteArrays.validateBounds(rawData, offset, extensionLength);

        if(client) {
            return new ClientKeyShareExtension(type, rawData, offset, extensionLength);
        } else {
            return new ServerKeyShareExtension(type, rawData, offset, extensionLength);
        }
    }

    protected KeyShareExtension(ExtensionType type, short extensionLength) {
        super(type, extensionLength);
    }

    protected void readEntries(byte[] rawData, int cursor, int end) {
        while (cursor < end) {
            KeyShareEntry entry = readEntry(rawData, cursor);
            cursor += entry.size();
        }
    }

    protected KeyShareEntry readEntry(byte[] rawData, int cursor) {
        KeyShareEntry entry = new KeyShareEntry(rawData, cursor);
        entries.add(entry);
        return entry;
    }

    @Override
    public String toString() {
        return type.name() + " " + entries.toString();
    }

    protected byte[] entriesToByteArray() {
        List<byte[]> list = new ArrayList<>();

        for (KeyShareEntry entry : entries) {
            list.add(entry.toByteArray());
        }

        return ByteArrays.concatenate(list);
    }

}
