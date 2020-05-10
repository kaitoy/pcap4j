package org.pcap4j.packet.tls.extensions.keyshare;

import org.pcap4j.packet.namednumber.tls.ExtensionType;
import org.pcap4j.util.ByteArrays;

import java.util.Arrays;
import java.util.List;

public class ServerKeyShareExtension extends KeyShareExtension {

    private static final int KEY_SHARE_ENTRY_OFFSET = 0;

    public ServerKeyShareExtension(ExtensionType type, byte[] rawData, int offset, short extensionLength) {
        super(type, extensionLength);
        readEntry(rawData, KEY_SHARE_ENTRY_OFFSET + offset);
    }

    public ServerKeyShareExtension(ExtensionType type, short extensionLength, List<KeyShareEntry> entries) {
        super(type, extensionLength);
        this.entries = entries;
    }

    @Override
    public byte[] toByteArray() {
        return ByteArrays.concatenate(Arrays.asList(
                ByteArrays.toByteArray(type.value()),
                ByteArrays.toByteArray(extensionLength),
                entriesToByteArray()));
    }
}
