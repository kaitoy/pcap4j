package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.INET6_ADDRESS_SIZE_IN_BYTES;
import static org.pcap4j.util.ByteArrays.SHORT_SIZE_IN_BYTES;

import java.net.Inet6Address;
import java.util.ArrayList;
import java.util.List;

import org.pcap4j.packet.AbstractPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.namednumber.NotApplicable;
import org.pcap4j.util.ByteArrays;

public class IcmpV6HomeAgentAddressDiscoveryReplyPacket extends AbstractPacket {

    /**
     *
     */
    private static final long serialVersionUID = 8080366373921919970L;

    private final IcmpV6HomeAgentAddressDiscoveryReplyHeader header;
    private final Packet payload;

    /**
     * A static factory method.
     * This method validates the arguments by {@link ByteArrays#validateBounds(byte[], int, int)},
     * which may throw exceptions undocumented here.
     * 
     * @param rawData rawData
     * @param offset offset
     * @param length length
     * @return a new IcmpV6HomeAgentAddressDiscoveryReplyPacket object.
     * @throws IllegalRawDataException if parsing the raw data fails.
     */
    public static IcmpV6HomeAgentAddressDiscoveryReplyPacket newPacket(
            byte[] rawData, int offset, int length) throws IllegalRawDataException {
        ByteArrays.validateBounds(rawData, offset, length);
        return new IcmpV6HomeAgentAddressDiscoveryReplyPacket(rawData, offset, length);
    }

    private IcmpV6HomeAgentAddressDiscoveryReplyPacket(
            byte[] rawData, int offset, int length) throws IllegalRawDataException {
        this.header = new IcmpV6HomeAgentAddressDiscoveryReplyHeader(rawData, offset, length);

        int payloadLength = length - header.length();
        if (payloadLength > 0) {
            this.payload = PacketFactories.getFactory(Packet.class, NotApplicable.class)
                    .newInstance(rawData, offset + header.length(), payloadLength, NotApplicable.UNKNOWN);
        } else {
            this.payload = null;
        }
    }

    private IcmpV6HomeAgentAddressDiscoveryReplyPacket(Builder builder) {
        this.header = new IcmpV6HomeAgentAddressDiscoveryReplyHeader(builder);
        this.payload = builder.payloadBuilder != null ? builder.payloadBuilder.build() : null;
    }

    @Override
    public IcmpV6HomeAgentAddressDiscoveryReplyHeader getHeader() {
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
        private Inet6Address homeAgentAddresses;
        private Packet.Builder payloadBuilder;

        /**
         *
         */
        public Builder() {
            // Do nothing, just used to create a Builder without fields setting
        }

        private Builder(IcmpV6HomeAgentAddressDiscoveryReplyPacket packet) {
            this.identifier = packet.header.identifier;
            this.reserved = packet.header.reserved;
            this.homeAgentAddresses = packet.header.homeAgentAddresses;
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

        /**
         * @param homeAgentAddresses homeAgentAddresses
         * @return this Builder object for method chaining.
         */
        public Builder homeAgentAddresses(Inet6Address homeAgentAddresses) {
            this.homeAgentAddresses = homeAgentAddresses;
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
        public IcmpV6HomeAgentAddressDiscoveryReplyPacket build() {
            return new IcmpV6HomeAgentAddressDiscoveryReplyPacket(this);
        }

    }

    public static final class IcmpV6HomeAgentAddressDiscoveryReplyHeader extends AbstractHeader {

        /*
         * 0                   1                   2                   3
         * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * |           Identifier          |             Reserved          |
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * |                                                               |
         * +                                                               +
         * |                                                               |
         * +                      Home Agent Addresses                     +
         * |                                                               |
         * +                                                               +
         * |                                                               |
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         */
        private static final long serialVersionUID = 7184228144196703852L;

        private static final int IDENTIFIER_OFFSET = 0;
        private static final int IDENTIFIER_SIZE = SHORT_SIZE_IN_BYTES;
        private static final int RESERVED_OFFSET = IDENTIFIER_OFFSET + IDENTIFIER_SIZE;
        private static final int RESERVED_SIZE = SHORT_SIZE_IN_BYTES;
        private static final int HOME_AGENT_ADDRESSES_OFFSET = RESERVED_OFFSET + RESERVED_SIZE;
        private static final int HOME_AGENT_ADDRESSES_SIZE = INET6_ADDRESS_SIZE_IN_BYTES;
        private static final int ICMPV6_HOME_AGENT_ADDRESS_DISCOVERY_REPLY_HEADER_SIZE = HOME_AGENT_ADDRESSES_OFFSET
                + HOME_AGENT_ADDRESSES_SIZE;

        private final short identifier;
        private final short reserved;
        private final Inet6Address homeAgentAddresses;

        private IcmpV6HomeAgentAddressDiscoveryReplyHeader(byte[] rawData, int offset, int length)
                throws IllegalRawDataException {
            if (length < ICMPV6_HOME_AGENT_ADDRESS_DISCOVERY_REPLY_HEADER_SIZE) {
                StringBuilder sb = new StringBuilder();
                sb.append("The data is too short to build an ICMPv6 Home Agent Address Discovery Reply Header(")
                        .append(ICMPV6_HOME_AGENT_ADDRESS_DISCOVERY_REPLY_HEADER_SIZE)
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
            this.homeAgentAddresses = ByteArrays.getInet6Address(rawData, HOME_AGENT_ADDRESSES_OFFSET + offset);

        }

        private IcmpV6HomeAgentAddressDiscoveryReplyHeader(Builder builder) {
            this.identifier = builder.identifier;
            this.reserved = builder.reserved;
            this.homeAgentAddresses = builder.homeAgentAddresses;
        }

        public short getIdentifier() {
            return identifier;
        }

        public short getReserved() {
            return reserved;
        }

        public Inet6Address getHomeAgentAddresses() {
            return homeAgentAddresses;
        }

        @Override
        protected List<byte[]> getRawFields() {
            List<byte[]> rawFields = new ArrayList<byte[]>();
            rawFields.add(ByteArrays.toByteArray(identifier));
            rawFields.add(ByteArrays.toByteArray(reserved));
            rawFields.add(ByteArrays.toByteArray(homeAgentAddresses));
            return rawFields;
        }

        @Override
        public int length() {
            return ICMPV6_HOME_AGENT_ADDRESS_DISCOVERY_REPLY_HEADER_SIZE;
        }

        @Override
        protected String buildString() {
            StringBuilder sb = new StringBuilder();
            String ls = System.getProperty("line.separator");

            sb.append("[ICMPv6 Home Agent Address Discovery Reply Header (")
                    .append(length())
                    .append(" bytes)]")
                    .append(ls);
            sb.append("  Identifier: ")
                    .append(identifier)
                    .append(ls);
            sb.append("  Reserved: ")
                    .append(reserved)
                    .append(ls);
            sb.append("  HomeAgentAddresses: ")
                    .append(homeAgentAddresses)
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

            IcmpV6HomeAgentAddressDiscoveryReplyHeader other = (IcmpV6HomeAgentAddressDiscoveryReplyHeader) obj;
            return this.identifier == other.identifier
                    && this.reserved == other.reserved
                    && this.homeAgentAddresses.equals(other.homeAgentAddresses);
        }

        @Override
        protected int calcHashCode() {
            int result = 17;
            result = 31 * result + identifier;
            result = 31 * result + reserved;
            result = 31 * result + homeAgentAddresses.hashCode();
            return result;
        }
    }
}
