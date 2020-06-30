package org.pcap4j.packet;

import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.namednumber.GtpV1ExtNRUPduType;
import org.pcap4j.packet.namednumber.GtpV1ExtensionHeaderType;
import org.pcap4j.packet.namednumber.NotApplicable;
import org.pcap4j.util.ByteArrays;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class GtpV1ExtNRUPacket extends AbstractPacket {
    private static final long serialVersionUID = -4565759636621525022L;

    private final GtpV1ExtNRUHeader header;
    private final Packet payload;

    /**
     * A static factory method. This method validates the arguments by {@link
     * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
     *
     * @param rawData rawData
     * @param offset offset
     * @param length length
     * @return a new GtpV1ExtNRUPacket object.
     * @throws org.pcap4j.packet.IllegalRawDataException if parsing the raw data fails.
     */
    public static GtpV1ExtNRUPacket newPacket(byte[] rawData, int offset, int length)
            throws IllegalRawDataException {
        ByteArrays.validateBounds(rawData, offset, length);
        return new GtpV1ExtNRUPacket(rawData, offset, length);
    }
    private GtpV1ExtNRUPacket(byte[] rawData, int offset, int length)
            throws IllegalRawDataException {
        this.header = new GtpV1ExtNRUHeader(rawData, offset, length);

        int payloadLength = length - header.length();
        if (payloadLength > 0) {
            Packet nextPacket;
            if (!header.nextExtensionHeaderType.equals(
                    GtpV1ExtensionHeaderType.NO_MORE_EXTENSION_HEADERS)) {
                nextPacket =
                        PacketFactories.getFactory(Packet.class, GtpV1ExtensionHeaderType.class)
                                .newInstance(
                                        rawData,
                                        offset + header.length(),
                                        payloadLength,
                                        header.nextExtensionHeaderType);
            } else {
                nextPacket =
                        PacketFactories.getFactory(Packet.class, NotApplicable.class)
                                .newInstance(
                                        rawData, offset + header.length(), payloadLength, NotApplicable.UNKNOWN);
            }
            this.payload = nextPacket;
        } else {
            this.payload = null;
        }
    }



    private GtpV1ExtNRUPacket(Builder builder) {

        if (builder == null) {
            throw new NullPointerException("builder must not be null.");
        }
        if ((builder.reportPolling & 0xFE) != 0) {
            throw new IllegalArgumentException(
                    "(builder.reportPolling & 0xFE) must be zero. builder.reportPolling: " + builder.reportPolling);
        }
        if ((builder.sn & 0xFF000000) != 0) {
            throw new IllegalArgumentException(
                    "(builder.sn & 0xFF000000) must be zero. builder.sn: " + builder.sn);
        }
        this.payload = builder.payloadBuilder != null ? builder.payloadBuilder.build() : null;
        this.header = new GtpV1ExtNRUHeader(builder);
    }
    @Override
    public GtpV1ExtNRUHeader getHeader() {
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


    public static final class Builder extends AbstractBuilder
            implements LengthBuilder<GtpV1ExtNRUPacket> {
        byte extensionHeaderLength;
        GtpV1ExtNRUPduType pduType;
        byte spare1;
        byte dlDiscardBlocks;
        byte dlFlush;
        byte reportPolling;

        byte spare2;
        boolean assistanceInfoReportPoolingFlag;
        boolean retransmissionFlag;

        int sn;
        //add fields to support  dlflush=1 and dldiscardblock=1
        int dlDiscardNrPdcpPduSn;
        byte dlDiscardNoOfBlocks;
        List<Integer> dlDiscardNrPdcpSnStartList;
        List<Byte> discardedBlockSizeList;
        byte[] padding;
        GtpV1ExtensionHeaderType nextExtensionHeaderType;

        boolean correctLengthAtBuild;

        private Packet.Builder payloadBuilder;

        private boolean paddingAtBuild;

        /** */
        public Builder() {
            // Do nothing, just used to create a Builder without fields setting
        }

        /** @param packet packet */
        public Builder(GtpV1ExtNRUPacket packet){

            this.extensionHeaderLength = packet.header.extensionHeaderLength;
            this.pduType = packet.header.pduType;
            this.spare1 = packet.header.spare1;
            this.dlDiscardBlocks = packet.header.dlDiscardBlocks;
            this.dlFlush = packet.header.dlFlush;
            this.reportPolling = packet.header.reportPolling;
            this.spare2 = packet.header.spare2;
            this.retransmissionFlag = packet.header.retransmissionFlag;
            this.assistanceInfoReportPoolingFlag = packet.header.assistanceInfoReportPoolingFlag;
            this.sn = packet.header.sn;
            if (this.dlFlush!=0){
                this.dlDiscardNrPdcpPduSn=packet.header.dlDiscardNrPdcpPduSn;
            }
            if (this.dlDiscardBlocks!=0){
                this.dlDiscardNoOfBlocks=packet.header.dlDiscardNoOfBlocks;
                this.dlDiscardNrPdcpSnStartList=packet.header.dlDiscardNrPdcpSnStartList;
                this.discardedBlockSizeList=packet.header.discardedBlockSizeList;
            }
            this.padding = packet.header.padding;
            this.nextExtensionHeaderType = packet.header.nextExtensionHeaderType;
            this.payloadBuilder = packet.payload != null ? packet.payload.getBuilder() : null;
        }


        /**
         * @param extensionHeaderLength Extension Header Length
         * @return this Builder object for method chaining.
         */
        public Builder extensionHeaderLength(byte extensionHeaderLength) {
            this.extensionHeaderLength = extensionHeaderLength;
            return this;
        }

        /**
         * @param pduType PDU type
         * @return this Builder object for method chaining.
         */
        public Builder pduType(GtpV1ExtNRUPduType pduType) {
            this.pduType = pduType;
            return this;
        }

        /**
         * @param spare1 first spare field
         * @return this Builder object for method chaining.
         */
        public Builder spare1(byte spare1) {
            this.spare1 = spare1;
            return this;
        }

        /**
         * @param dlDiscardBlocks
         * @return this Builder object for method chaining.
         */
        public Builder dlDiscardBlocks(byte dlDiscardBlocks) {
            this.dlDiscardBlocks = dlDiscardBlocks;
            return this;
        }

        /**
         * @param dlFlush
         * @return this Builder object for method chaining.
         */
        public Builder dlFlush(byte dlFlush) {
            this.dlFlush = dlFlush;
            return this;
        }

        /**
         * @param reportPolling
         * @return this Builder object for method chaining.
         */
        public Builder reportPolling(byte reportPolling) {
            this.reportPolling = reportPolling;
            return this;
        }

        /**
         * @param spare2 second spare field
         * @return this Builder object for method chaining.
         */
        public Builder spare2(Byte spare2) {
            this.spare2 = spare2;
            return this;
        }

        /**
         * @param retransmissionFlag
         * @return this Builder object for method chaining.
         */
        public Builder retransmissionFlag(boolean retransmissionFlag) {
            this.retransmissionFlag = retransmissionFlag;
            return this;
        }

        /**
         * @param assistanceInfoReportPoolingFlag
         * @return this Builder object for method chaining.
         */
        public Builder assistanceInfoReportPoolingFlag(boolean assistanceInfoReportPoolingFlag) {
            this.assistanceInfoReportPoolingFlag = assistanceInfoReportPoolingFlag;
            return this;
        }

        /**
         * @param sn
         * @return this Builder object for method chaining.
         */
        public Builder sn(int sn) {
            this.sn = sn;
            return this;
        }

        /**
         *
         * @param dlDiscardNrPdcpPduSn
         * @return this Builder object for method chaining.
         */
        public Builder dlDiscardNrPdcpPduSn(int dlDiscardNrPdcpPduSn){
            this.dlDiscardNrPdcpPduSn=dlDiscardNrPdcpPduSn;
            return this;
        }

        /**
         *
         * @param dlDiscardNoOfBlocks
         * @return this Builder object for method chaining.
         */
        public Builder dlDiscardNoOfBlocks(byte dlDiscardNoOfBlocks){
            this.dlDiscardNoOfBlocks=dlDiscardNoOfBlocks;
            return this;
        }

        public Builder dlDiscardNrPdcpSnStartList(List<Integer> dlDiscardNrPdcpSnStartList) {
            if (this.dlDiscardBlocks != 0) {
                this.dlDiscardNrPdcpSnStartList = dlDiscardNrPdcpSnStartList;
            }
            return this;
        }

        public Builder discardedBlockSizeList(List<Byte> discardedBlockSizeList) {
            if (this.dlDiscardBlocks != 0) {
                this.discardedBlockSizeList = discardedBlockSizeList;
            }
            return this;
        }
        /**
         * @param padding
         * @return this Builder object for method chaining.
         */
        public Builder padding(byte[] padding) {
            this.padding = padding;
            return this;
        }

        /**
         *
         * @param nextExtensionHeaderType nextExtensionHeaderType
         * @return this Builder object for method chaining.
         */
        public Builder nextExtensionHeaderType(GtpV1ExtensionHeaderType nextExtensionHeaderType) {
            this.nextExtensionHeaderType = nextExtensionHeaderType;
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
        public Builder correctLengthAtBuild(boolean correctLengthAtBuild) {
            this.correctLengthAtBuild = correctLengthAtBuild;
            return this;
        }

        /**
         * @param paddingAtBuild paddingAtBuild
         * @return this Builder object for method chaining.
         */
        public Builder paddingAtBuild(boolean paddingAtBuild) {
            this.paddingAtBuild = paddingAtBuild;
            return this;
        }

        /**
         * Build a GtpV1ExtNRUPacket object using values set to this object.
         *
         * @return a new GtpV1ExtNRUPacket object
         */
        @Override
        public GtpV1ExtNRUPacket build() {
            return new GtpV1ExtNRUPacket(this);
        }
    }

    /**
     * GTP NR-U Extension Header
     *
     * <pre style="white-space: pre;">
     * 8        7       6       5       4       3       2       1
     * +-------+-------+-------+-------+-------+-------+-------+-------+
     * |            Extension Header Length                            |
     * +-------+-------+-------+-------+-------+-------+-------+-------+
     * |         PDU Type              |Spare  | DL    |  DL   | Report|  1
     * |                               |       |Discard| Flush |polling|
     * |                               |       |Blocks |       |       |
     * +-------+-------+-------+-------+-------+-------+-------+-------+
     * |           Spare               |Report | User  |Assista|Retrans|  1
     * |                               |Deliver| data  |nce inf|mission|
     * |                               |ed     |existen|o.Polli| flag  |
     * |                               |       |ce flag|ng flag|       |
     * +-------+-------+-------+-------+-------+-------+-------+-------+
     * |                   NR-U Sequence Number                        |  3
     * +-------+-------+-------+-------+-------+-------+-------+-------+
     * |                   DL discard NR PDCP PDU SN                   |  0/3
     * +-------+-------+-------+-------+-------+-------+-------+-------+
     * |                   DL discard Number of blocks                 |  0/1
     * +-------+-------+-------+-------+-------+-------+-------+-------+
     * |             DL discard NR PDCP PDU SN start (first block)     |  0/3
     * +-------+-------+-------+-------+-------+-------+-------+-------+
     * |               Discarded Block size (first block)              |  0/1
     * +-------+-------+-------+-------+-------+-------+-------+-------+
     * |                             ...                               |
     * +-------+-------+-------+-------+-------+-------+-------+-------+
     * |             DL discard NR PDCP PDU SN start (last block)      |  0/3
     * +-------+-------+-------+-------+-------+-------+-------+-------+
     * |               Discarded Block size (last block)               |  0/1
     * +-------+-------+-------+-------+-------+-------+-------+-------+
     * |                    Padding                                    |  0-3
     * +-------+-------+-------+-------+-------+-------+-------+-------+
     * |                 Next Extension Header Type                    |
     * +-------+-------+-------+-------+-------+-------+-------+-------+
     *  </pre>
     *
     * @see <a href=
     *      "https://www.etsi.org/deliver/etsi_ts/138400_138499/138425/15.02.00_60/ts_138425v150200p.pdf">ETSI
     *      TS 138 425 V15.2.0</a>
     */
    public static class GtpV1ExtNRUHeader extends AbstractHeader {

        private static final long serialVersionUID = 4625438436488959845L;

        private static final int EXTENSION_HEADER_LENGTH_OFFSET = 0;
        private static final int EXTENSION_HEADER_LENGTH_SIZE = ByteArrays.BYTE_SIZE_IN_BYTES;
        /**
         * PDU Type 0
         */
        private static final int PDU_TYPE_AND_SPARE_AND_DLDB_AND_DLF_AND_RP_OFFSET = EXTENSION_HEADER_LENGTH_OFFSET + EXTENSION_HEADER_LENGTH_SIZE;
        private static final int PDU_TYPE_AND_SPARE_SIZE = ByteArrays.BYTE_SIZE_IN_BYTES;
        private static final int SPARE_AND_RD_AND_UEF_AND_AIRPF_AND_RF_OFFSET =
                PDU_TYPE_AND_SPARE_AND_DLDB_AND_DLF_AND_RP_OFFSET + PDU_TYPE_AND_SPARE_SIZE;
        private static final int SPARE_AND_RD_AND_UEF_AND_AIRPF_AND_RF_SIZE = ByteArrays.BYTE_SIZE_IN_BYTES;

        public static final int SEQUENCE_NUMBER_OFFSET =
                SPARE_AND_RD_AND_UEF_AND_AIRPF_AND_RF_OFFSET + SPARE_AND_RD_AND_UEF_AND_AIRPF_AND_RF_SIZE;
        public static final int SEQUENCE_NUMBER_SIZE = ByteArrays.BYTE_SIZE_IN_BYTES * 3;
        public static final int DL_DISCARD_NR_PDCP_PDU_SN_OFFSET = SEQUENCE_NUMBER_OFFSET
                + SEQUENCE_NUMBER_SIZE;

        private int DL_DISCARD_NR_PDCP_PDU_SN_START__AND_BLOCK_SIZE_SIZE = ByteArrays.INT_SIZE_IN_BYTES;;

        private static final int NEXT_EXTENSION_HEADER_TYPE_SIZE = ByteArrays.BYTE_SIZE_IN_BYTES;
        private static final int GTPV1_NRU_SESSION_CONTAINER_EXTENSION_MIN_LENGTH = DL_DISCARD_NR_PDCP_PDU_SN_OFFSET
                + NEXT_EXTENSION_HEADER_TYPE_SIZE;


        private final GtpV1ExtNRUPduType pduType;
        private final byte spare1;
        private final byte dlDiscardBlocks;
        private final byte dlFlush;
        private final byte reportPolling;

        private final byte spare2;
        private final boolean retransmissionFlag;
        private final boolean assistanceInfoReportPoolingFlag;

        private final int sn;
        //add fields to support  dlflush=1 and dldiscardblock=1
        private int dlDiscardNrPdcpPduSn;
        private byte dlDiscardNoOfBlocks;
        private List<Integer> dlDiscardNrPdcpSnStartList;
        private List<Byte> discardedBlockSizeList;
        private final byte[] padding;
        private final GtpV1ExtensionHeaderType nextExtensionHeaderType;
        private byte extensionHeaderLength;
        GtpV1ExtNRUHeader(byte[] rawData, int offset, int length) throws IllegalRawDataException {
            if (length < GTPV1_NRU_SESSION_CONTAINER_EXTENSION_MIN_LENGTH) {
                StringBuilder sb = new StringBuilder(80);
                sb.append("The data is too short to build an GTP NR-U extension header(")
                        .append(GTPV1_NRU_SESSION_CONTAINER_EXTENSION_MIN_LENGTH)
                        .append(" bytes). data: ")
                        .append(ByteArrays.toHexString(rawData, " "))
                        .append(", offset: ")
                        .append(offset)
                        .append(", length: ")
                        .append(length);
                throw new IllegalRawDataException(sb.toString());
            }
            this.extensionHeaderLength =
                    ByteArrays.getByte(rawData, EXTENSION_HEADER_LENGTH_OFFSET + offset);

            byte pduTypeAndSpareAndDldbAndDlfAndRp = ByteArrays
                    .getByte(rawData, PDU_TYPE_AND_SPARE_AND_DLDB_AND_DLF_AND_RP_OFFSET + offset);
            this.pduType = GtpV1ExtNRUPduType.getInstance((byte) ((pduTypeAndSpareAndDldbAndDlfAndRp & 0xF0) >>> 4));

            this.spare1 = (byte) ((pduTypeAndSpareAndDldbAndDlfAndRp & 0x08) >> 3);
            this.dlDiscardBlocks = (byte) ((pduTypeAndSpareAndDldbAndDlfAndRp & 0x04) >> 2);
            this.dlFlush = (byte) ((pduTypeAndSpareAndDldbAndDlfAndRp & 0x02) >> 1);
            this.reportPolling = (byte) (pduTypeAndSpareAndDldbAndDlfAndRp & 0x01);

            byte spareAndRdAndUefAndArpfAndRf = ByteArrays
                    .getByte(rawData, SPARE_AND_RD_AND_UEF_AND_AIRPF_AND_RF_OFFSET + offset);
            this.spare2 = (byte) ((spareAndRdAndUefAndArpfAndRf & 0xFC) >> 2);
            this.assistanceInfoReportPoolingFlag = (spareAndRdAndUefAndArpfAndRf & 0x02) != 0;
            this.retransmissionFlag = (spareAndRdAndUefAndArpfAndRf & 0x01) != 0;

            int snInRaw = ByteArrays.getInt(rawData, SEQUENCE_NUMBER_OFFSET + offset);
            this.sn = snInRaw >>> 8;

            // add support for dlFlush=1,when dlFlush=1 ,set the dlDiscardNrPdcpPduSn.
            int dlDiscardNrPdcpPduSnSize=0;
            if (this.dlFlush!=0){
                dlDiscardNrPdcpPduSnSize=ByteArrays.BYTE_SIZE_IN_BYTES*3;
                int dlDiscardNrPdcpPduSnInRaw = ByteArrays.getInt(rawData, DL_DISCARD_NR_PDCP_PDU_SN_OFFSET + offset);
                this.dlDiscardNrPdcpPduSn = dlDiscardNrPdcpPduSnInRaw >>> 8;
            }
            int currentOffsetInHeader = DL_DISCARD_NR_PDCP_PDU_SN_OFFSET + dlDiscardNrPdcpPduSnSize;
            int dlDiscardNumberOfBlocksSize=0;
            if (this.dlDiscardBlocks != 0) {
                dlDiscardNumberOfBlocksSize = ByteArrays.BYTE_SIZE_IN_BYTES;
                this.dlDiscardNoOfBlocks = ByteArrays.getByte(rawData, currentOffsetInHeader + offset);

                currentOffsetInHeader+=dlDiscardNumberOfBlocksSize;
                dlDiscardNrPdcpSnStartList = new ArrayList<Integer>();
                discardedBlockSizeList = new ArrayList<Byte>();
                for (int i = 0; i < dlDiscardNoOfBlocks; i++) {
                    int discardSnStartAndBlockSizeInRaw = ByteArrays.getInt(rawData,
                            currentOffsetInHeader + offset);
                    this.dlDiscardNrPdcpSnStartList.add(discardSnStartAndBlockSizeInRaw >>> 8);
                    this.discardedBlockSizeList.add((byte) (discardSnStartAndBlockSizeInRaw & 0xFF));
                    currentOffsetInHeader += DL_DISCARD_NR_PDCP_PDU_SN_START__AND_BLOCK_SIZE_SIZE;
                }
            }

            int headerLength = (0xFF & extensionHeaderLength) * 4;
            if (length < headerLength) {
                StringBuilder sb = new StringBuilder(100);
                sb.append("The data is too short to build an GTP NR-U extension header(")
                        .append(headerLength)
                        .append(" bytes). data: ")
                        .append(ByteArrays.toHexString(rawData, " "))
                        .append(", offset: ")
                        .append(offset)
                        .append(", length: ")
                        .append(length);
                throw new IllegalRawDataException(sb.toString());
            }

            int paddingLength = headerLength - currentOffsetInHeader - 1;
            if (paddingLength != 0) {
                this.padding =
                        ByteArrays.getSubArray(rawData, currentOffsetInHeader + offset, paddingLength);
                currentOffsetInHeader += padding.length;
            } else {
                this.padding = new byte[0];
            }

            this.nextExtensionHeaderType =
                    GtpV1ExtensionHeaderType.getInstance(
                            ByteArrays.getByte(rawData, currentOffsetInHeader + offset));
        }
        GtpV1ExtNRUHeader(Builder builder) {
            this.pduType = builder.pduType;
            this.spare1 = builder.spare1;
            this.dlDiscardBlocks = builder.dlDiscardBlocks;
            this.dlFlush = builder.dlFlush;
            this.reportPolling = builder.reportPolling;
            this.spare2 = builder.spare2;
            this.retransmissionFlag = builder.retransmissionFlag;
            this.assistanceInfoReportPoolingFlag = builder.assistanceInfoReportPoolingFlag;
            this.sn = builder.sn;
            if (this.dlFlush!=0){
                this.dlDiscardNrPdcpPduSn = builder.dlDiscardNrPdcpPduSn;
            }
            if (this.dlDiscardBlocks!=0){
                this.dlDiscardNoOfBlocks = builder.dlDiscardNoOfBlocks;
                this.dlDiscardNrPdcpSnStartList = builder.dlDiscardNrPdcpSnStartList;
                this.discardedBlockSizeList = builder.discardedBlockSizeList;
            }
            this.nextExtensionHeaderType = builder.nextExtensionHeaderType;

            if (builder.paddingAtBuild) {
                int mod = measureLengthWithoutPadding() % 4;
                if (mod != 0) {
                    this.padding = new byte[4 - mod];
                } else {
                    this.padding = new byte[0];
                }
            } else {
                if (builder.padding != null) {
                    this.padding = new byte[builder.padding.length];
                    System.arraycopy(builder.padding, 0, padding, 0, padding.length);
                } else {
                    this.padding = new byte[0];
                }
            }

            if (builder.correctLengthAtBuild) {
                this.extensionHeaderLength = (byte) (length() / 4);
            } else {
                this.extensionHeaderLength = builder.extensionHeaderLength;
            }
        }
        private int measureLengthWithoutPadding() {
            int lengthWithoutPadding=7;
            if(this.dlFlush!=0){
                lengthWithoutPadding+=3;
            }
            if (this.dlDiscardBlocks!=0){
                lengthWithoutPadding+=1;
                lengthWithoutPadding+=this.dlDiscardNoOfBlocks*DL_DISCARD_NR_PDCP_PDU_SN_START__AND_BLOCK_SIZE_SIZE;
            }
            return lengthWithoutPadding;
        }

        /** @return extensionHeaderLength */
        public byte getExtensionHeaderLength() {
            return extensionHeaderLength;
        }

        /** @return extensionHeaderLength as int */
        public int getExtensionHeaderLengthAsInt() {
            return 0xFF & extensionHeaderLength;
        }

        public GtpV1ExtNRUPduType getPduType() {
            return pduType;
        }

        public byte getSpare1() {
            return spare1;
        }

        public byte getDlDiscardBlocks() {
            return dlDiscardBlocks;
        }

        public byte getDlFlush() {
            return dlFlush;
        }

        public byte getReportPolling() {
            return reportPolling;
        }

        public byte getSpare2() {
            return spare2;
        }

        public boolean isRetransmissionFlag() {
            return retransmissionFlag;
        }

        public boolean isAssistanceInfoReportPoolingFlag() {
            return assistanceInfoReportPoolingFlag;
        }

        public int getNruSN() {
            return sn;
        }

        public int getDlDiscardNrPdcpPduSn() {
            return dlDiscardNrPdcpPduSn;
        }

        public byte getDlDiscardNoOfBlocks() {
            return dlDiscardNoOfBlocks;
        }

        public List<Integer> getDlDiscardNrPdcpSnStartList() {
            return dlDiscardNrPdcpSnStartList;
        }

        public List<Byte> getDiscardedBlockSizeList() {
            return discardedBlockSizeList;
        }

        /** @return padding */
        public byte[] getPadding() {
            return Arrays.copyOf(padding, padding.length);
        }

        public GtpV1ExtensionHeaderType getNextExtensionHeaderType() {
            return nextExtensionHeaderType;
        }

        @Override
        protected List<byte[]> getRawFields() {
            List<byte[]> rawFields = new ArrayList<byte[]>();
            rawFields.add(ByteArrays.toByteArray(extensionHeaderLength));
            byte firstByte = 0;
            byte secondByte = 0;
            firstByte |= pduType.value() << 4 | (spare1 & 0x01) << 3 | (dlDiscardBlocks & 0x01) << 2 | (dlFlush & 0x01) << 1 | reportPolling & 0x01;
            secondByte |= (spare2 & 0x3F) << 2;
            if (assistanceInfoReportPoolingFlag) {
                secondByte |= 0x02;
            }
            if (retransmissionFlag) {
                secondByte |= 0x01;
            }
            rawFields.add(ByteArrays.toByteArray(firstByte));
            rawFields.add(ByteArrays.toByteArray(secondByte));
            rawFields.add(ByteArrays.getSubArray(ByteArrays.toByteArray(sn), 1));
            if(dlFlush!=0){
                rawFields.add(ByteArrays.getSubArray(ByteArrays.toByteArray(dlDiscardNrPdcpPduSn),1));
            }
            if (dlDiscardBlocks!=0){
                rawFields.add(ByteArrays.toByteArray(dlDiscardNoOfBlocks));
                for (int i=0;i<dlDiscardNoOfBlocks;i++){
                    rawFields.add(ByteArrays.getSubArray(ByteArrays.toByteArray(dlDiscardNrPdcpSnStartList.get(i)), 1));
                    rawFields.add(ByteArrays.toByteArray(discardedBlockSizeList.get(i)));
                }
            }

            if (padding != null) {
                rawFields.add(padding);
            }
            rawFields.add(ByteArrays.toByteArray(nextExtensionHeaderType.value()));
            return rawFields;
        }

        @Override
        protected int calcLength() {
            return measureLengthWithoutPadding() + padding.length;
        }
        @Override
        public String buildString() {
            StringBuilder sb = new StringBuilder();
            String ls = System.getProperty("line.separator");
            sb.append("[GTP NR-U Extension Header (")
                    .append(this.length())
                    .append(" bytes)]")
                    .append(ls)
                    .append("  Extension Header Length: ")
                    .append(extensionHeaderLength)
                    .append(" (")
                    .append(extensionHeaderLength * 4)
                    .append(" bytes)")
                    .append(ls)
                    .append("  pdu type: ")
                    .append(pduType)
                    .append(ls)
                    .append("  spare 1: 0x")
                    .append(ByteArrays.toHexString(spare1, ""))
                    .append(ls)
                    .append("  DL Discard Blocks:  ")
                    .append(dlDiscardBlocks)
                    .append(ls)
                    .append("  DL Flush:  ")
                    .append(dlFlush)
                    .append(ls)
                    .append("  Report Polling:  ")
                    .append(reportPolling)
                    .append(ls)
                    .append("  spare 2: 0x")
                    .append(ByteArrays.toHexString(spare2, ""))
                    .append(ls)
                    .append("  Retransmission Flag:  ")
                    .append(retransmissionFlag)
                    .append(ls)
                    .append("  Assistance Info Report Pooling Flag:  ")
                    .append(assistanceInfoReportPoolingFlag)
                    .append(ls)
                    .append("  NR-U Sequence Number:  ")
                    .append(sn)
                    .append(ls);
            if (this.dlFlush!=0){
                sb.append("  DlDisDL discard NR PDCP PDU SN:  ").append(this.dlDiscardNrPdcpPduSn).append(ls);
            }
            if (this.dlDiscardBlocks!=0){
                sb.append("  DL discard Number of blocks:  ")
                        .append(this.dlDiscardNoOfBlocks)
                        .append(ls);
                for (int i = 1; i <= dlDiscardNrPdcpSnStartList.size(); i++) {
                    sb.append(String.format("  DL discard NR PDCP PDU SN start ( %s block):  ", i))
                            .append(dlDiscardNrPdcpSnStartList.get(i)).append(ls);
                    sb.append(String.format("  Discarded Block size ( %s block):  ", i))
                            .append(discardedBlockSizeList.get(i)).append(ls);
                }
            }

            if (padding.length != 0) {
                sb.append("  Padding: ").append(ByteArrays.toHexString(padding, " ")).append(ls);
            }
            sb.append("  Next Extension Header Type: ").append(nextExtensionHeaderType).append(ls);
            return sb.toString();

        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            if (!super.equals(o)) return false;

            GtpV1ExtNRUHeader that = (GtpV1ExtNRUHeader) o;

            if (extensionHeaderLength != that.extensionHeaderLength) {
                return false;
            }
            if (pduType != that.pduType) return false;
            if (spare1 != that.spare1) {
                return false;
            }
            if (dlDiscardBlocks != that.dlDiscardBlocks) return false;
            if (dlFlush != that.dlFlush) return false;
            if (reportPolling != that.reportPolling) return false;
            if (spare2 != that.spare2) {
                return false;
            }
            if (retransmissionFlag != that.retransmissionFlag) return false;
            if (assistanceInfoReportPoolingFlag != that.assistanceInfoReportPoolingFlag) return false;
            if (sn != that.sn) return false;
            if (dlFlush!=0){
                if (dlDiscardNrPdcpPduSn!=that.dlDiscardNrPdcpPduSn) return false;
            }
            if (dlDiscardBlocks!=0){
                if (dlDiscardBlocks!=that.dlDiscardBlocks)
                    return false;
                if (dlDiscardNrPdcpSnStartList.size()!=that.dlDiscardNrPdcpSnStartList.size()){
                    return false;
                }else if(!dlDiscardNrPdcpSnStartList.containsAll(that.dlDiscardNrPdcpSnStartList)|| !that.dlDiscardNrPdcpSnStartList.containsAll(dlDiscardNrPdcpSnStartList)){
                    return false;
                }
                if (discardedBlockSizeList.size()!=that.discardedBlockSizeList.size()){
                    return false;
                }else if (!discardedBlockSizeList.containsAll(that.discardedBlockSizeList) || !that.discardedBlockSizeList.containsAll(discardedBlockSizeList)){
                    return false;
                }

            }
            if (!Arrays.equals(padding, that.padding)) {
                return false;
            }
            return nextExtensionHeaderType.equals(that.nextExtensionHeaderType);
        }

        @Override
        protected int calcHashCode() {
            int result = 17;
            result = 31 * result + (int) extensionHeaderLength;
            result = 37 * result + pduType.hashCode();
            result = 31 * result + (int) spare1;
            result = 37 * result + dlDiscardBlocks;
            result = 37 * result + dlFlush;
            result = 37 * result + reportPolling;
            result = 31 * result + (int) spare2;
            result = 37 * result + (retransmissionFlag ? 1 : 0);
            result = 37 * result + (assistanceInfoReportPoolingFlag ? 1 : 0);
            result = 37 * result + sn;
            if (this.dlFlush!=0){
                result = 37 * result + dlDiscardNrPdcpPduSn;
            }
            if (this.dlDiscardBlocks!=0){
                result = 37 * result + dlDiscardNoOfBlocks;
                result = 37 * result + dlDiscardNrPdcpSnStartList.hashCode();
                result = 37 * result + discardedBlockSizeList.hashCode();
            }
            if (padding!=null) {
                result = 37 * result + Arrays.hashCode(padding);
            }
            result = 37 * result + (nextExtensionHeaderType != null ? nextExtensionHeaderType.hashCode() : 0);
            return result;
        }
    }

}