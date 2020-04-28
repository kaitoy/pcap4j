package org.pcap4j.packet.tls.records;

import org.pcap4j.util.ByteArrays;

public class ChangeCipherSpecRecord implements TlsRecord {

    /**
    0x0 - Change Cipher Spec Message
    0x1 - End
     */

    private byte changeCipherSpecMessage;

    public static ChangeCipherSpecRecord newInstance(byte[] rawData, int offset, int length) {
        ByteArrays.validateBounds(rawData, offset, length);
        return new ChangeCipherSpecRecord(rawData, offset);
    }

    private ChangeCipherSpecRecord(byte[] rawData, int offset) {
        this.changeCipherSpecMessage = ByteArrays.getByte(rawData, offset);
    }

    @Override
    public String toString() {
        return "  Change Cipher Spec Message: " + changeCipherSpecMessage;
    }

    @Override
    public byte[] toByteArray() {
        return new byte[] { changeCipherSpecMessage };
    }
}
