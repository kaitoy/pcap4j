package org.pcap4j.packet.tls.extensions.keyshare;

import org.pcap4j.util.ByteArrays;
import org.pcap4j.packet.namednumber.tls.KeyGroup;

import static org.pcap4j.util.ByteArrays.SHORT_SIZE_IN_BYTES;

public class KeyShareEntry {

    private static final int GROUP_OFFSET = 0;
    private static final int KEY_EXHANGE_LENGTH_OFFSET = GROUP_OFFSET + SHORT_SIZE_IN_BYTES;
    private static final int KEY_EXCHANGE_OFFSET = KEY_EXHANGE_LENGTH_OFFSET + SHORT_SIZE_IN_BYTES;

    private KeyGroup group;
    private short keyExhangeLength;
    private byte[] keyExchange;

    public KeyShareEntry(byte[] rawData, int offset) {
        this.group = KeyGroup.getInstance(ByteArrays.getShort(rawData, GROUP_OFFSET + offset));
        this.keyExhangeLength = ByteArrays.getShort(rawData, KEY_EXHANGE_LENGTH_OFFSET + offset);
        keyExchange = new byte[keyExhangeLength];
        System.arraycopy(rawData, KEY_EXCHANGE_OFFSET + offset, keyExchange, 0, keyExhangeLength);
    }

    public int size() {
        return SHORT_SIZE_IN_BYTES + SHORT_SIZE_IN_BYTES + keyExhangeLength;
    }

    @Override
    public String toString() {
        return group.name();
    }
}
