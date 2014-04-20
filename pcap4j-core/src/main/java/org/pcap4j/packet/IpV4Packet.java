/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2014  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.*;
import java.io.Serializable;
import java.net.Inet4Address;
import java.util.ArrayList;
import java.util.List;
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpV4OptionType;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.NA;
import org.pcap4j.util.ByteArrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public final class IpV4Packet extends AbstractPacket {

  // http://tools.ietf.org/html/rfc791

  /**
   *
   */
  private static final long serialVersionUID = -3907669810080927342L;

  private static final Logger logger = LoggerFactory.getLogger(IpV4Packet.class);

  private final IpV4Header header;
  private final Packet payload;

  /**
   *
   * @param rawData
   * @return a new IpV4Packet object.
   */
  public static IpV4Packet newPacket(byte[] rawData) {
    return new IpV4Packet(rawData);
  }

  private IpV4Packet(byte[] rawData) {
    this.header = new IpV4Header(rawData);

    int remainingRawDataLength = rawData.length - header.length();
    int totalLength = header.getTotalLengthAsInt();
    int payloadLength;
    if (totalLength == 0) {
      logger.debug("Total Length is 0. Assuming segmentation offload to be working.");
      payloadLength = remainingRawDataLength;
    }
    else {
      payloadLength = totalLength - header.length();
    }

    byte[] rawPayload;
    if (payloadLength > remainingRawDataLength) {
      rawPayload
        = ByteArrays.getSubArray(
            rawData,
            header.length(),
            remainingRawDataLength
          );
    }
    else {
      rawPayload
        = ByteArrays.getSubArray(
            rawData,
            header.length(),
            payloadLength
          );
    }

    if (header.getMoreFragmentFlag() || header.getFlagmentOffset() != 0) {
      this.payload = FragmentedPacket.newPacket(rawPayload);
    }
    else {
      this.payload
        = PacketFactories.getFactory(Packet.class, IpNumber.class)
            .newInstance(rawPayload, header.getProtocol());
    }
  }

  private IpV4Packet(Builder builder) {
    if (
         builder == null
      || builder.version == null
      || builder.tos == null
      || builder.protocol == null
      || builder.srcAddr == null
      || builder.dstAddr == null
      || builder.payloadBuilder == null
    ) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ").append(builder)
        .append(" builder.version: ").append(builder.version)
        .append(" builder.tos: ").append(builder.tos)
        .append(" builder.protocol: ").append(builder.protocol)
        .append(" builder.srcAddr: ").append(builder.srcAddr)
        .append(" builder.dstAddr: ").append(builder.dstAddr)
        .append(" builder.payloadBuilder: ").append(builder.payloadBuilder);
      throw new NullPointerException(sb.toString());
    }

    this.payload = builder.payloadBuilder.build();
    this.header = new IpV4Header(builder, payload);
  }

  @Override
  public IpV4Header getHeader() {
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

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.1
   */
  public static final
  class Builder extends AbstractBuilder
  implements ChecksumBuilder<IpV4Packet>, LengthBuilder<IpV4Packet> {

    private IpVersion version;
    private byte ihl;
    private IpV4Tos tos;
    private short totalLength;
    private short identification;
    private boolean reservedFlag;
    private boolean dontFragmentFlag;
    private boolean moreFragmentFlag;
    private short flagmentOffset;
    private byte ttl;
    private IpNumber protocol;
    private short headerChecksum;
    private Inet4Address srcAddr;
    private Inet4Address dstAddr;
    private List<IpV4Option> options;
    private byte[] padding;
    private Packet.Builder payloadBuilder;
    private boolean correctChecksumAtBuild;
    private boolean correctLengthAtBuild;
    private boolean paddingAtBuild;

    /**
     *
     */
    public Builder() {}

    /**
     *
     * @param packet
     */
    public Builder(IpV4Packet packet) {
      this.version = packet.header.version;
      this.ihl = packet.header.ihl;
      this.tos = packet.header.tos;
      this.totalLength = packet.header.totalLength;
      this.identification = packet.header.identification;
      this.reservedFlag = packet.header.reservedFlag;
      this.dontFragmentFlag = packet.header.dontFragmentFlag;
      this.moreFragmentFlag = packet.header.moreFragmentFlag;
      this.flagmentOffset = packet.header.flagmentOffset;
      this.ttl = packet.header.ttl;
      this.protocol = packet.header.protocol;
      this.headerChecksum = packet.header.headerChecksum;
      this.srcAddr = packet.header.srcAddr;
      this.dstAddr = packet.header.dstAddr;
      this.options = packet.header.options;
      this.padding = packet.header.padding;
      this.payloadBuilder = packet.payload.getBuilder();
    }

    /**
     *
     * @param version
     * @return this Builder object for method chaining.
     */
    public Builder version(IpVersion version) {
      this.version = version;
      return this;
    }

    /**
     *
     * @param ihl
     * @return this Builder object for method chaining.
     */
    public Builder ihl(byte ihl) {
      this.ihl = ihl;
      return this;
    }

    /**
     *
     * @param tos
     * @return this Builder object for method chaining.
     */
    public Builder tos(IpV4Tos tos) {
      this.tos = tos;
      return this;
    }

    /**
     *
     * @param totalLength
     * @return this Builder object for method chaining.
     */
    public Builder totalLength(short totalLength) {
      this.totalLength = totalLength;
      return this;
    }

    /**
     *
     * @param identification
     * @return this Builder object for method chaining.
     */
    public Builder identification(short identification) {
      this.identification = identification;
      return this;
    }

    /**
     *
     * @param reservedFlag
     * @return this Builder object for method chaining.
     */
    public Builder reservedFlag(boolean reservedFlag) {
      this.reservedFlag = reservedFlag;
      return this;
    }

    /**
     *
     * @param dontFragmentFlag
     * @return this Builder object for method chaining.
     */
    public Builder dontFragmentFlag(boolean dontFragmentFlag) {
      this.dontFragmentFlag = dontFragmentFlag;
      return this;
    }

    /**
     *
     * @param moreFragmentFlag
     * @return this Builder object for method chaining.
     */
    public Builder moreFragmentFlag(boolean moreFragmentFlag) {
      this.moreFragmentFlag = moreFragmentFlag;
      return this;
    }

    /**
     *
     * @param flagmentOffset
     * @return this Builder object for method chaining.
     */
    public Builder flagmentOffset(short flagmentOffset) {
      this.flagmentOffset = flagmentOffset;
      return this;
    }

    /**
     *
     * @param ttl
     * @return this Builder object for method chaining.
     */
    public Builder ttl(byte ttl) {
      this.ttl = ttl;
      return this;
    }

    /**
     *
     * @param protocol
     * @return this Builder object for method chaining.
     */
    public Builder protocol(IpNumber protocol) {
      this.protocol = protocol;
      return this;
    }

    /**
     *
     * @param headerChecksum
     * @return this Builder object for method chaining.
     */
    public Builder headerChecksum(short headerChecksum) {
      this.headerChecksum = headerChecksum;
      return this;
    }

    /**
     *
     * @param srcAddr
     * @return this Builder object for method chaining.
     */
    public Builder srcAddr(Inet4Address srcAddr) {
      this.srcAddr = srcAddr;
      return this;
    }

    /**
     *
     * @param dstAddr
     * @return this Builder object for method chaining.
     */
    public Builder dstAddr(Inet4Address dstAddr) {
      this.dstAddr = dstAddr;
      return this;
    }

    /**
     *
     * @param options
     * @return this Builder object for method chaining.
     */
    public Builder options(List<IpV4Option> options) {
      this.options = options;
      return this;
    }

    /**
     *
     * @param padding
     * @return this Builder object for method chaining.
     */
    public Builder padding(byte[] padding) {
      this.padding = padding;
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

    public Builder correctChecksumAtBuild(boolean correctChecksumAtBuild) {
      this.correctChecksumAtBuild = correctChecksumAtBuild;
      return this;
    }

    public Builder correctLengthAtBuild(boolean correctLengthAtBuild) {
      this.correctLengthAtBuild = correctLengthAtBuild;
      return this;
    }

    /**
     *
     * @param paddingAtBuild
     * @return this Builder object for method chaining.
     */
    public Builder paddingAtBuild(boolean paddingAtBuild) {
      this.paddingAtBuild = paddingAtBuild;
      return this;
    }

    @Override
    public IpV4Packet build() {
      return new IpV4Packet(this);
    }

  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.1
   */
  public static final class IpV4Header extends AbstractHeader {

    /*  0                              16                            31
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |Version|  IHL  |Type of Service|           Total Length        |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |         Identification        |Flags|      Fragment Offset    |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |  Time to Live |    Protocol   |         Header Checksum       |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                       Source Address                          |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                    Destination Address                        |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                    Options                    |    Padding    |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */

    /**
     *
     */
    private static final long serialVersionUID = -337098234014128285L;

    private static final int VERSION_AND_IHL_OFFSET
      = 0;
    private static final int VERSION_AND_IHL_SIZE
      = BYTE_SIZE_IN_BYTES;
    private static final int TOS_OFFSET
      = VERSION_AND_IHL_OFFSET + VERSION_AND_IHL_SIZE;
    private static final int TOS_SIZE
      = BYTE_SIZE_IN_BYTES;
    private static final int TOTAL_LENGTH_OFFSET
      = TOS_OFFSET + TOS_SIZE;
    private static final int TOTAL_LENGTH_SIZE
      = SHORT_SIZE_IN_BYTES;
    private static final int IDENTIFICATION_OFFSET
      = TOTAL_LENGTH_OFFSET + TOTAL_LENGTH_SIZE;
    private static final int IDENTIFICATION_SIZE
      = SHORT_SIZE_IN_BYTES;
    private static final int FLAGS_AND_FLAGMENT_OFFSET_OFFSET
      = IDENTIFICATION_OFFSET + IDENTIFICATION_SIZE;
    private static final int FLAGS_AND_FLAGMENT_OFFSET_SIZE
      = SHORT_SIZE_IN_BYTES;
    private static final int TTL_OFFSET
      = FLAGS_AND_FLAGMENT_OFFSET_OFFSET + FLAGS_AND_FLAGMENT_OFFSET_SIZE;
    private static final int TTL_SIZE
      = BYTE_SIZE_IN_BYTES;
    private static final int PROTOCOL_OFFSET
      = TTL_OFFSET + TTL_SIZE;
    private static final int PROTOCOL_SIZE
      = BYTE_SIZE_IN_BYTES;
    private static final int HEADER_CHECKSUM_OFFSET
      = PROTOCOL_OFFSET + PROTOCOL_SIZE;
    private static final int HEADER_CHECKSUM_SIZE
      = SHORT_SIZE_IN_BYTES;
    private static final int SRC_ADDR_OFFSET
      = HEADER_CHECKSUM_OFFSET + HEADER_CHECKSUM_SIZE;
    private static final int SRC_ADDR_SIZE
      = INET4_ADDRESS_SIZE_IN_BYTES;
    private static final int DST_ADDR_OFFSET
      = SRC_ADDR_OFFSET + SRC_ADDR_SIZE;
    private static final int DST_ADDR_SIZE
      = INET4_ADDRESS_SIZE_IN_BYTES;
    private static final int OPTIONS_OFFSET
      = DST_ADDR_OFFSET + DST_ADDR_SIZE;

    private static final int MIN_IPV4_HEADER_SIZE
      = DST_ADDR_OFFSET + DST_ADDR_SIZE;

    private final IpVersion version;
    private final byte ihl;
    private final IpV4Tos tos;
    private final short totalLength;
    private final short identification;
    private final boolean reservedFlag;
    private final boolean dontFragmentFlag;
    private final boolean moreFragmentFlag;
    private final short flagmentOffset;
    private final byte ttl;
    private final IpNumber protocol;
    private final short headerChecksum;
    private final Inet4Address srcAddr;
    private final Inet4Address dstAddr;
    private final List<IpV4Option> options;
    private final byte[] padding;

    private IpV4Header(byte[] rawData) {
      if (rawData.length < MIN_IPV4_HEADER_SIZE) {
        StringBuilder sb = new StringBuilder(110);
        sb.append("The data is too short to build an IPv4 header. ")
          .append("It must be at least ")
          .append(MIN_IPV4_HEADER_SIZE)
          .append(" bytes. data: ")
          .append(ByteArrays.toHexString(rawData, " "));
        throw new IllegalRawDataException(sb.toString());
      }

      byte versionAndIhl
        = ByteArrays.getByte(rawData, VERSION_AND_IHL_OFFSET);
      this.version = IpVersion.getInstance(
                       (byte)((versionAndIhl & 0xF0) >> 4)
                     );
      this.ihl = (byte)(versionAndIhl & 0x0F);

      this.tos
        = PacketFactories.getFactory(
            IpV4Tos.class, NA.class
          ).newInstance(ByteArrays.getSubArray(rawData, TOS_OFFSET, BYTE_SIZE_IN_BYTES));
      this.totalLength
        = ByteArrays.getShort(rawData, TOTAL_LENGTH_OFFSET);
      this.identification
        = ByteArrays.getShort(rawData, IDENTIFICATION_OFFSET);

      short flagsAndFlagmentOffset
        = ByteArrays.getShort(rawData, FLAGS_AND_FLAGMENT_OFFSET_OFFSET);
      this.reservedFlag = (flagsAndFlagmentOffset & 0x8000) != 0;
      this.dontFragmentFlag = (flagsAndFlagmentOffset & 0x4000) != 0;
      this.moreFragmentFlag = (flagsAndFlagmentOffset & 0x2000) != 0;
      this.flagmentOffset = (short)(flagsAndFlagmentOffset & 0x1FFF);

      this.ttl
        = ByteArrays.getByte(rawData, TTL_OFFSET);
      this.protocol
        = IpNumber
            .getInstance(ByteArrays.getByte(rawData, PROTOCOL_OFFSET));
      this.headerChecksum
        = ByteArrays.getShort(rawData, HEADER_CHECKSUM_OFFSET);
      this.srcAddr
        = ByteArrays.getInet4Address(rawData, SRC_ADDR_OFFSET);
      this.dstAddr
        = ByteArrays.getInet4Address(rawData, DST_ADDR_OFFSET);

      int headerLength = ihl * 4;
      if (rawData.length < headerLength) {
        StringBuilder sb = new StringBuilder(110);
        sb.append("The data is too short to build an IPv4 header(")
          .append(headerLength)
          .append(" bytes). data: ")
          .append(ByteArrays.toHexString(rawData, " "));
        throw new IllegalRawDataException(sb.toString());
      }

      this.options = new ArrayList<IpV4Option>();
      int currentOffset = OPTIONS_OFFSET;
      while (currentOffset < headerLength) {
        byte[] optRawData = ByteArrays.getSubArray(
                              rawData,
                              currentOffset,
                              headerLength - currentOffset
                            );
        IpV4OptionType type = IpV4OptionType.getInstance(optRawData[0]);
        IpV4Option newOne
          = PacketFactories
              .getFactory(IpV4Option.class, IpV4OptionType.class)
                 .newInstance(optRawData, type);
        options.add(newOne);
        currentOffset += newOne.length();

        if (newOne.getType().equals(IpV4OptionType.END_OF_OPTION_LIST)) {
          break;
        }
      }

      this.padding
        = ByteArrays.getSubArray(
            rawData, currentOffset, headerLength - currentOffset
          );
    }

    private IpV4Header(Builder builder, Packet payload) {
      if ((builder.flagmentOffset & 0xE000) != 0) {
        throw new IllegalArgumentException(
                "Invalid flagmentOffset: " + builder.flagmentOffset
              );
      }

      this.version = builder.version;
      this.tos = builder.tos;
      this.identification = builder.identification;
      this.reservedFlag = builder.reservedFlag;
      this.dontFragmentFlag = builder.dontFragmentFlag;
      this.moreFragmentFlag = builder.moreFragmentFlag;
      this.flagmentOffset = builder.flagmentOffset;
      this.ttl = builder.ttl;
      this.protocol = builder.protocol;
      this.srcAddr = builder.srcAddr;
      this.dstAddr = builder.dstAddr;
      if (builder.options != null) {
        this.options = new ArrayList<IpV4Option>(builder.options);
      }
      else {
        this.options = new ArrayList<IpV4Option>(0);
      }

      if (builder.paddingAtBuild) {
        int mod = measureLengthWithoutPadding() % 4;
        if (mod != 0) {
          this.padding = new byte[4 - mod];
        }
        else {
          this.padding = new byte[0];
        }
      }
      else {
        if (builder.padding != null) {
          this.padding = new byte[builder.padding.length];
          System.arraycopy(builder.padding, 0, padding, 0, padding.length);
        }
        else {
          this.padding = new byte[0];
        }
      }

      if (builder.correctLengthAtBuild) {
        this.ihl = (byte)(length() / 4);

        if (payload != null) {
          this.totalLength = (short)(payload.length() + length());
        }
        else {
          this.totalLength = builder.totalLength;
        }
      }
      else {
        if ((builder.ihl & 0xF0) != 0) {
          throw new IllegalArgumentException("Invalid ihl: " + builder.ihl);
        }
        this.ihl = builder.ihl;
        this.totalLength = builder.totalLength;
      }

      if (builder.correctChecksumAtBuild) {
        if (PacketPropertiesLoader.getInstance().ipV4CalcChecksum()) {
          headerChecksum = calcHeaderChecksum();
        }
        else {
          headerChecksum = (short)0;
        }
      }
      else {
        this.headerChecksum = builder.headerChecksum;
      }
    }

    private short calcHeaderChecksum() {
      // If call getRawData() here, rawData will be cached with
      // an invalid checksum in some cases.
      // To avoid it, use buildRawData() instead.
      byte[] data = buildRawData();

      for (int i = 0; i < HEADER_CHECKSUM_SIZE; i++) {
        data[HEADER_CHECKSUM_OFFSET + i] = (byte)0;
      }

      return ByteArrays.calcChecksum(data);
    }

    /**
     *
     * @return version
     */
    public IpVersion getVersion() {
      return version;
    }

    /**
     *
     * @return ihl
     */
    public byte getIhl() {
      return ihl;
    }

    /**
     *
     * @return tos
     */
    public IpV4Tos getTos() {
      return tos;
    }

    /**
     *
     * @return totalLength
     */
    public short getTotalLength() {
      return totalLength;
    }

    /**
     *
     * @return totalLength
     */
    public int getTotalLengthAsInt() {
      return 0xFFFF & totalLength;
    }

    /**
     *
     * @return identification
     */
    public short getIdentification() {
      return identification;
    }

    /**
     *
     * @return identification
     */
    public int getIdentificationAsInt() {
      return 0xFFFF & identification;
    }

    /**
     *
     * @return reservedFlag
     */
    public boolean getReservedFlag() {
      return reservedFlag;
    }

    /**
     *
     * @return dontFragmentFlag
     */
    public boolean getDontFragmentFlag() {
      return dontFragmentFlag;
    }

    /**
     *
     * @return moreFragmentFlag
     */
    public boolean getMoreFragmentFlag() {
      return moreFragmentFlag;
    }

    /**
     *
     * @return flagmentOffset
     */
    public short getFlagmentOffset() {
      return flagmentOffset;
    }

    /**
     *
     * @return ttl
     */
    public byte getTtl() {
      return ttl;
    }

    /**
     *
     * @return ttl
     */
    public int getTtlAsInt() {
      return 0xFF & ttl;
    }

    /**
     *
     * @return protocol
     */
    public IpNumber getProtocol() {
      return protocol;
    }

    /**
     *
     * @return headerChecksum
     */
    public short getHeaderChecksum() {
      return headerChecksum;
    }

    /**
     *
     * @return srcAddr
     */
    public Inet4Address getSrcAddr() {
      return srcAddr;
    }

    /**
     *
     * @return dstAddr
     */
    public Inet4Address getDstAddr() {
      return dstAddr;
    }

    /**
     *
     * @return options
     */
    public List<IpV4Option> getOptions() {
      return new ArrayList<IpV4Option>(options);
    }

    /**
     *
     * @return padding
     */
    public byte[] getPadding() {
      byte[] copy = new byte[padding.length];
      System.arraycopy(padding, 0, copy, 0, padding.length);
      return copy;
    }

    /**
     *
     * @param acceptZero
     * @return true if the packet represented by this object has a valid checksum;
     *         false otherwise.
     */
    public boolean hasValidChecksum(boolean acceptZero) {
      if (headerChecksum == 0) {
        if (acceptZero) { return true; }
        else { return false; }
      }
      return calcHeaderChecksum() == headerChecksum;
    }

    @Override
    protected List<byte[]> getRawFields() {
      byte flags = 0;
      if (moreFragmentFlag) { flags = (byte)1; }
      if (dontFragmentFlag) { flags = (byte)(flags | 2); }
      if (reservedFlag) { flags = (byte)(flags | 4); }

      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(ByteArrays.toByteArray((byte)((version.value() << 4) | ihl)));
      rawFields.add(new byte[] {tos.value()});
      rawFields.add(ByteArrays.toByteArray(totalLength));
      rawFields.add(ByteArrays.toByteArray(identification));
      rawFields.add(ByteArrays.toByteArray((short)((flags << 13) | flagmentOffset)));
      rawFields.add(ByteArrays.toByteArray(ttl));
      rawFields.add(ByteArrays.toByteArray(protocol.value()));
      rawFields.add(ByteArrays.toByteArray(headerChecksum));
      rawFields.add(ByteArrays.toByteArray(srcAddr));
      rawFields.add(ByteArrays.toByteArray(dstAddr));
      for (IpV4Option o: options) {
        rawFields.add(o.getRawData());
      }
      rawFields.add(padding);
      return rawFields;
    }

    private int measureLengthWithoutPadding() {
      int len = 0;
      for (IpV4Option o: options) {
        len += o.length();
      }
      return len + MIN_IPV4_HEADER_SIZE;
    }

    @Override
    protected int calcLength() {
      return measureLengthWithoutPadding() + padding.length;
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[IPv4 Header (")
        .append(length())
        .append(" bytes)]")
        .append(ls);
      sb.append("  Version: ")
        .append(version)
        .append(ls);
      sb.append("  IHL: ")
        .append(ihl)
        .append(" (")
        .append(ihl * 4)
        .append(" [bytes])")
        .append(ls);
      sb.append("  TOS: ")
        .append(tos)
        .append(ls);
      sb.append("  Total length: ")
        .append(getTotalLengthAsInt())
        .append(" [bytes]")
        .append(ls);
      sb.append("  Identification: ")
        .append(getIdentificationAsInt())
        .append(ls);
      sb.append("  Flags: (Reserved, Don't Fragment, More Fragment) = (")
        .append(getReservedFlag())
        .append(", ")
        .append(getDontFragmentFlag())
        .append(", ")
        .append(getMoreFragmentFlag())
        .append(")")
        .append(ls);
      sb.append("  Flagment offset: ")
        .append(flagmentOffset)
        .append(" (")
        .append(flagmentOffset * 8)
        .append(" [bytes])")
        .append(ls);
      sb.append("  TTL: ")
        .append(getTtlAsInt())
        .append(ls);
      sb.append("  Protocol: ")
        .append(protocol)
        .append(ls);
      sb.append("  Header checksum: 0x")
        .append(ByteArrays.toHexString(headerChecksum, ""))
        .append(ls);
      sb.append("  Source address: ")
        .append(srcAddr)
        .append(ls);
      sb.append("  Destination address: ")
        .append(dstAddr)
        .append(ls);
      for (IpV4Option opt: options) {
        sb.append("  Option: ")
          .append(opt)
          .append(ls);
      }
      if (padding.length != 0) {
        sb.append("  Padding: 0x")
          .append(ByteArrays.toHexString(padding, " "))
          .append(ls);
      }

      return sb.toString();
    }

  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.11
   */
  public interface IpV4Option extends Serializable {

    // /* must implement if use PropertiesBasedIpV4OptionFactory */
    // public static IpV4Option newInstance(byte[] rawData);

    /**
     *
     * @return type
     */
    public IpV4OptionType getType();

    /**
     *
     * @return length
     */
    public int length();

    /**
     *
     * @return raw data
     */
    public byte[] getRawData();

  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.11
   */
  public interface IpV4Tos extends Serializable {

    // /* must implement if use PropertiesBasedIpV4TosFactory */
    // public static IpV4Tos newInstance(byte value);

    /**
     *
     * @return value
     */
    public byte value();

  }

}
