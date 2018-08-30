package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.SHORT_SIZE_IN_BYTES;

import java.util.ArrayList;
import java.util.List;

import org.pcap4j.packet.AbstractPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.namednumber.NotApplicable;
import org.pcap4j.util.ByteArrays;

/**
 *
 */
public class IcmpV6MobilePrefixSolicitationPacket extends AbstractPacket {

    /**
     *
     */
    private static final long serialVersionUID = -6996114480884459960L;

    private final IcmpV6MobilePrefixSolicitationHeader header;
    private final Packet payload;

    /**
     * A static factory method.
     * This method validates the arguments by {@link ByteArrays#validateBounds(byte[], int, int)},
     * which may throw exceptions undocumented here.
     * 
     * @param rawData rawData
     * @param offset offset
     * @param length length
     * @return a new IcmpV6MobilePrefixSolicitationPacket object.
     * @throws IllegalRawDataException if parsing the raw data fails.
     */
    public static IcmpV6MobilePrefixSolicitationPacket newPacket(
            byte[] rawData, int offset, int length) throws IllegalRawDataException {
        ByteArrays.validateBounds(rawData, offset, length);
        return new IcmpV6MobilePrefixSolicitationPacket(rawData, offset, length);
    }

    private IcmpV6MobilePrefixSolicitationPacket(
            byte[] rawData, int offset, int length) throws IllegalRawDataException {
        this.header = new IcmpV6MobilePrefixSolicitationHeader(rawData, offset, length);

        int payloadLength = length - header.length();
        if (payloadLength > 0) {
            this.payload = PacketFactories.getFactory(Packet.class, NotApplicable.class)
                    .newInstance(rawData, offset + header.length(), payloadLength, NotApplicable.UNKNOWN);
        } else {
            this.payload = null;
        }
    }

    private IcmpV6MobilePrefixSolicitationPacket(Builder builder) {
        this.header = new IcmpV6MobilePrefixSolicitationHeader(builder);
        this.payload = builder.payloadBuilder != null ? builder.payloadBuilder.build() : null;
    }

    @Override
    public IcmpV6MobilePrefixSolicitationHeader getHeader() {
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

    public static final class Builder extends AbstractBuilder {

        private short identifier;
        private short reserved;
        private Packet.Builder payloadBuilder;

        /**
         *
         */
        public Builder() {
            // Do nothing, just used to create a Builder without fields setting
        }

        private Builder(IcmpV6MobilePrefixSolicitationPacket packet) {
            this.identifier = packet.header.identifier;
            this.reserved = packet.header.reserved;
            this.payloadBuilder = packet.payload != null ? packet.payload.getBuilder() : null;
        }

        /**
         * @param identifier identifier
         * @return this Builder object for method chaining.
         */
        public Builder identifier(short identifier) {
            this.identifier = identifier;
            return this;
        }

        /**
         * @param reserved reserved
         * @return this Builder object for method chaining.
         */
        public Builder reserved(short reserved) {
            this.reserved = reserved;
            return this;
        }

        @Override
        public Builder payloadBuilder(Packet.Builder payloadBuilder) {
            this.payloadBuilder = payloadBuilder;
            return this;
        }

        @Override
        public Packet.Builder getPayloadBuilder() {
            return payloadBuilder;
        }

        @Override
        public IcmpV6MobilePrefixSolicitationPacket build() {
            return new IcmpV6MobilePrefixSolicitationPacket(this);
        }

    }

    public static final class IcmpV6MobilePrefixSolicitationHeader extends AbstractHeader {

        /*
         *  0                            15                              31
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * |          Identifier           |            Reserved           |
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         */

        /**
         *
         */
        private static final long serialVersionUID = -2991706817314703570L;

        private static final int IDENTIFIER_OFFSET = 0;
        private static final int IDENTIFIER_SIZE = SHORT_SIZE_IN_BYTES;
        private static final int RESERVED_OFFSET = IDENTIFIER_OFFSET + IDENTIFIER_SIZE;
        private static final int RESERVED_SIZE = SHORT_SIZE_IN_BYTES;
        private static final int ICMPV6_MOBILE_PREFIX_SOLICITATION_HEADER_SIZE = RESERVED_OFFSET + RESERVED_SIZE;

        private final short identifier;
        private final short reserved;

        private IcmpV6MobilePrefixSolicitationHeader(byte[] rawData, int offset, int length)
                throws IllegalRawDataException {
            if (length < ICMPV6_MOBILE_PREFIX_SOLICITATION_HEADER_SIZE) {
                StringBuilder sb = new StringBuilder();
                sb.append("The data is too short to build an ICMPv6 Mobile Prefix Solicitation Header(")
                        .append(ICMPV6_MOBILE_PREFIX_SOLICITATION_HEADER_SIZE)
                        .append(" bytes). data: ")
                        .append(ByteArrays.toHexString(rawData, " "))
                        .append(", offset: ")
                        .append(offset)
                        .append(", length: ")
                        .append(length);
                throw new IllegalRawDataException(sb.toString());
            }
            this.identifier = ByteArrays.getShort(rawData, IDENTIFIER_OFFSET + offset);
            this.reserved = ByteArrays.getShort(rawData, RESERVED_OFFSET + offset);
        }

        private IcmpV6MobilePrefixSolicitationHeader(Builder builder) {
            this.identifier = builder.identifier;
            this.reserved = builder.reserved;
        }

        public short getIdentifier() {
            return identifier;
        }

        public short getReserved() {
            return reserved;
        }

        @Override
        protected List<byte[]> getRawFields() {
            List<byte[]> rawFields = new ArrayList<byte[]>();
            rawFields.add(ByteArrays.toByteArray(identifier));
            rawFields.add(ByteArrays.toByteArray(reserved));
            return rawFields;
        }

        @Override
        public int length() {
            return ICMPV6_MOBILE_PREFIX_SOLICITATION_HEADER_SIZE;

        }

        @Override
        protected String buildString() {
            StringBuilder sb = new StringBuilder();
            String ls = System.getProperty("line.separator");

            sb.append("[ICMPv6 Mobile Prefix Solicitation Header (")
                    .append(length())
                    .append(" bytes)]")
                    .append(ls);
            sb.append("  Identifier: ")
                    .append(identifier)
                    .append(ls);
            sb.append("  Reserved: ")
                    .append(reserved)
                    .append(ls);
            return sb.toString();
        }

        @Override
        public boolean equals(Object obj) {
            if (obj == this) {
                return true;
            }
            if (obj == null) {
                return false;
            }
            if (!this.getClass().isInstance(obj)) {
                return false;
            }

            IcmpV6MobilePrefixSolicitationHeader other = (IcmpV6MobilePrefixSolicitationHeader) obj;
            return this.identifier == other.identifier
                    && this.reserved == other.reserved;
        }

        @Override
        protected int calcHashCode() {
            int result = 17;
            result = 31 * result + identifier;
            result = 31 * result + reserved;
            return result;
        }

    }
}
