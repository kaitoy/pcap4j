package org.pcap4j.packet;

import org.pcap4j.packet.namednumber.tls.ContentType;
import org.pcap4j.packet.namednumber.tls.TlsVersion;
import org.pcap4j.packet.tls.records.*;
import org.pcap4j.util.ByteArrays;

import java.util.ArrayList;
import java.util.List;

import static org.pcap4j.util.ByteArrays.BYTE_SIZE_IN_BYTES;
import static org.pcap4j.util.ByteArrays.SHORT_SIZE_IN_BYTES;

public class TlsPacket extends AbstractPacket {

    private final TlsPacket.TlsHeader header;
    private final Packet payload;

    public static TlsPacket newPacket(byte[] rawData, int offset, int length) throws IllegalRawDataException {
        ByteArrays.validateBounds(rawData, offset, length);
        return new TlsPacket(rawData, offset, length);
    }

    private TlsPacket(byte[] rawData, int offset, int length) throws IllegalRawDataException {
        this.header = new TlsPacket.TlsHeader(rawData, offset, length);

        int payloadLength = length - header.length();
        if (payloadLength > 0) {
            this.payload = TlsPacket.newPacket(rawData, offset + header.length(), payloadLength);
        } else {
            this.payload = null;
        }
    }

    private TlsPacket(TlsPacket.Builder builder) {
        if (builder == null) {
            throw new NullPointerException("builder: null");
        }

        this.payload = builder.payloadBuilder != null ? builder.payloadBuilder.build() : null;
        this.header = new TlsPacket.TlsHeader(builder);
    }

    @Override
    public TlsHeader getHeader() {
        return header;
    }

    @Override
    public Packet getPayload() {
        return payload;
    }

    @Override
    public Builder getBuilder() {
        return new Builder(this);
    }

    @Override
    protected String buildString() {
        StringBuilder sb = new StringBuilder(getHeader().toString());

        TlsPacket p = (TlsPacket) getPayload();

        if (p != null) {
            sb.append('\n');
            sb.append(p.toString());
        }

        return sb.toString();
    }

    public static final class TlsHeader extends AbstractHeader {

        /*
        0x0 - Content Type
        0x1 - Version
        0x3 - Length
        0x5 - Record content
         */

        private static final int CONTENT_TYPE_OFFSET = 0;
        private static final int VERSION_OFFSET = CONTENT_TYPE_OFFSET + BYTE_SIZE_IN_BYTES;
        private static final int LENGTH_OFFSET = VERSION_OFFSET + SHORT_SIZE_IN_BYTES;
        private static final int RECORD_OFFSET = LENGTH_OFFSET + SHORT_SIZE_IN_BYTES;

        private ContentType contentType;
        private TlsVersion version;
        private short recordLength;
        private TlsRecord record;

        private TlsHeader(Builder builder) {
            //TODO
        }

        private TlsHeader(byte[] rawData, int offset, int length) {
            ByteArrays.validateBounds(rawData, offset, RECORD_OFFSET);
            this.contentType = ContentType.getInstance(ByteArrays.getByte(rawData, CONTENT_TYPE_OFFSET + offset));
            this.version = TlsVersion.getInstance(ByteArrays.getShort(rawData, VERSION_OFFSET + offset));
            this.recordLength = ByteArrays.getShort(rawData, LENGTH_OFFSET + offset);

            if (contentType == ContentType.HANDSHAKE) {
                this.record = HandshakeRecord.newInstance(rawData, offset + RECORD_OFFSET, recordLength);
            } else if (contentType == ContentType.CHANGE_CIPHER_SPEC) {
                this.record = ChangeCipherSpecRecord.newInstance(rawData, offset + RECORD_OFFSET, recordLength);
            } else if (contentType == ContentType.APPLICATION_DATA) {
                this.record = ApplicationDataRecord.newInstance(rawData, offset + RECORD_OFFSET, recordLength);
            } else if (contentType == ContentType.ALERT) {
                this.record = AlertRecord.newInstance(rawData, offset + RECORD_OFFSET, recordLength);
            } else if (contentType == ContentType.HEARTBEAT) {
                this.record = HeartbeatRecord.newInstance(rawData, offset + RECORD_OFFSET, recordLength);
            } else {
                throw new IllegalArgumentException("Unknown content type: " + contentType);
            }
        }

        public ContentType getContentType() {
            return contentType;
        }

        public TlsVersion getVersion() {
            return version;
        }

        public TlsRecord getRecord() {
            return record;
        }

        @Override
        protected List<byte[]> getRawFields() {
            List<byte[]> rawFields = new ArrayList<>();
            rawFields.add(new byte[]{contentType.value()});
            rawFields.add(ByteArrays.toByteArray(version.value()));
            rawFields.add(ByteArrays.toByteArray(recordLength));
            rawFields.add(record.toByteArray());
            return rawFields;
        }

        @Override
        public int length() {
            return RECORD_OFFSET + recordLength;
        }

        @Override
        protected String buildString() {
            return "TLS Header [" + length() + " bytes]\n" +
                    "  Version: " + version + "\n" +
                    "  Type: " + contentType + "\n" +
                    record.toString();
        }
    }

    public static final class Builder extends AbstractBuilder {

        private Packet.Builder payloadBuilder;

        public Builder() {
        }

        public Builder(TlsPacket packet) {
            this.payloadBuilder = packet.payload != null ? packet.payload.getBuilder() : null;
        }

        @Override
        public Packet build() {
            return new TlsPacket(this);
        }
    }
}
