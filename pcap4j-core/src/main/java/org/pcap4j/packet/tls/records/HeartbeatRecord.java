package org.pcap4j.packet.tls.records;

import org.pcap4j.util.ByteArrays;
import org.pcap4j.packet.namednumber.tls.HeartbeatMessageType;

import java.util.Arrays;

import static org.pcap4j.util.ByteArrays.BYTE_SIZE_IN_BYTES;
import static org.pcap4j.util.ByteArrays.SHORT_SIZE_IN_BYTES;

public class HeartbeatRecord implements TlsRecord {

    //https://tools.ietf.org/html/rfc6520

    /**
     * 0x0 - type
     * 0x1 - payload length
     * 0x3 - payload
     * 0x3+length - padding
     */

    private static final int TYPE_OFFSET = 0;
    private static final int PAYLOAD_LENGTH_OFFSET = TYPE_OFFSET + BYTE_SIZE_IN_BYTES;
    private static final int PAYLOAD_OFFSET = PAYLOAD_LENGTH_OFFSET + SHORT_SIZE_IN_BYTES;

    private HeartbeatMessageType type;
    private short payloadLength;
    private byte[] payload;
    private byte[] padding;

    public static HeartbeatRecord newInstance(byte[] rawData, int offset, int length) {
        ByteArrays.validateBounds(rawData, offset, length);
        return new HeartbeatRecord(rawData, offset, length);
    }

    public HeartbeatRecord(byte[] rawData, int offset, int length) {
        this.type = HeartbeatMessageType.getInstance(ByteArrays.getByte(rawData, TYPE_OFFSET + offset));
        this.payloadLength = ByteArrays.getShort(rawData, PAYLOAD_LENGTH_OFFSET + offset);
        this.payload = ByteArrays.getSubArray(rawData, PAYLOAD_OFFSET + offset, payloadLength);
        this.padding = ByteArrays.getSubArray(rawData, PAYLOAD_OFFSET + payloadLength + offset);
    }

    public HeartbeatMessageType getType() {
        return type;
    }

    public byte[] getPayload() {
        return payload;
    }

    public byte[] getPadding() {
        return padding;
    }

    @Override
    public String toString() {
        return "  Heartbeat (" + type.name() +
                ") [" + payloadLength + " bytes payload, " +
                padding.length + " bytes padding]";
    }

    @Override
    public byte[] toByteArray() {
        return ByteArrays.concatenate(Arrays.asList(
                ByteArrays.toByteArray(type.value()),
                ByteArrays.toByteArray(payloadLength),
                payload,
                padding
        ));
    }
}
