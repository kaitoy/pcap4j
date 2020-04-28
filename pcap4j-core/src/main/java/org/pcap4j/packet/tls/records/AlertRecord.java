package org.pcap4j.packet.tls.records;

import org.pcap4j.util.ByteArrays;
import org.pcap4j.packet.namednumber.tls.AlertDescription;
import org.pcap4j.packet.namednumber.tls.AlertLevel;

import static org.pcap4j.util.ByteArrays.BYTE_SIZE_IN_BYTES;

public class AlertRecord implements TlsRecord {

    /**
     * 0x0 - Alert level
     * 0x1 - Alert description
     * 0x2 - End
     */

    private static final int LEVEL_OFFSET = 0;
    private static final int DESCRIPTION_OFFSET = LEVEL_OFFSET + BYTE_SIZE_IN_BYTES;

    private AlertLevel level;
    private AlertDescription description;

    public static AlertRecord newInstance(byte[] rawData, int offset, int length) {
        ByteArrays.validateBounds(rawData, offset, length);
        return new AlertRecord(rawData, offset);
    }

    public AlertRecord(byte[] rawData, int offset) {
        this.level = AlertLevel.getInstance(ByteArrays.getByte(rawData, LEVEL_OFFSET + offset));
        this.description = AlertDescription.getInstance(ByteArrays.getByte(rawData, DESCRIPTION_OFFSET + offset));
    }

    @Override
    public String toString() {
        return "  Alert [level: " + level.name() + ", description: " + description.name() + "]";
    }
}
