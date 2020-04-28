package org.pcap4j.packet.tls.extensions.keyshare;

import org.pcap4j.util.ByteArrays;
import org.pcap4j.packet.namednumber.tls.ExtensionType;

import static org.pcap4j.util.ByteArrays.SHORT_SIZE_IN_BYTES;

public class ClientKeyShareExtension extends KeyShareExtension {

    private static final int KEY_SHARE_LENGTH_OFFSET = 0;
    private static final int KEY_SHARE_ENTRY_OFFSET = KEY_SHARE_LENGTH_OFFSET + SHORT_SIZE_IN_BYTES;

    private short keyShareLength;

    public ClientKeyShareExtension(ExtensionType type, byte[] rawData, int offset, short extensionLength) {
        super(type, extensionLength);
        this.keyShareLength = ByteArrays.getShort(rawData, KEY_SHARE_LENGTH_OFFSET + offset);  // the field is not always there
        int cursor = KEY_SHARE_ENTRY_OFFSET + offset;
        ByteArrays.validateBounds(rawData, cursor, keyShareLength);
        readEntries(rawData, KEY_SHARE_ENTRY_OFFSET + offset, offset + keyShareLength);
    }

}
