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

    private byte[] content;

    private AlertLevel level;
    private AlertDescription description;

    public static AlertRecord newInstance(byte[] rawData, int offset, int length) {
        ByteArrays.validateBounds(rawData, offset, length);
        return new AlertRecord(rawData, offset, length);
    }

    public AlertRecord(byte[] rawData, int offset, int length) {
        this.content = ByteArrays.getSubArray(rawData, offset, length);
        this.level = AlertLevel.getInstance(ByteArrays.getByte(rawData, LEVEL_OFFSET + offset));

        if (level != AlertLevel.ENCRYPTED_ALERT) {
            this.description = AlertDescription.getInstance(ByteArrays.getByte(rawData, DESCRIPTION_OFFSET + offset));
        }
    }

    /**
     * Encrypted alert constructor
     */
    public AlertRecord(byte[] content) {
        this.content = content;
        this.level = AlertLevel.ENCRYPTED_ALERT;
    }

    public AlertRecord(AlertLevel level, AlertDescription description) {
        this.level = level;
        this.description = description;

        content = new byte[2];
        content[0] = level.value();
        content[1] = description.value();
    }

    @Override
    public byte[] toByteArray() {
        return content;
    }

    @Override
    public String toString() {
        if (level != AlertLevel.ENCRYPTED_ALERT) {
            return "  Alert [level: " + level.name() + ", description: " + description.name() + "]";
        } else {
            return "  Encrypted Alert [" + content.length + " bytes]";
        }
    }
}
