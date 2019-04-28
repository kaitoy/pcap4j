/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.BYTE_SIZE_IN_BYTES;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.factory.PacketFactory;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpV6OptionType;
import org.pcap4j.packet.namednumber.NotApplicable;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.10
 */
public abstract class IpV6ExtOptionsPacket extends AbstractPacket {

  private final Packet payload;

  /** */
  private static final long serialVersionUID = 416178196599916582L;

  /** */
  protected IpV6ExtOptionsPacket() {
    this.payload = null;
  }

  /**
   * @param rawData rawData
   * @param payloadOffset payloadOffset
   * @param payloadLength payloadLength
   * @param number number
   */
  protected IpV6ExtOptionsPacket(
      byte[] rawData, int payloadOffset, int payloadLength, IpNumber number) {
    PacketFactory<Packet, IpNumber> factory =
        PacketFactories.getFactory(Packet.class, IpNumber.class);
    Class<? extends Packet> nextPacketClass = factory.getTargetClass(number);
    Packet nextPacket;
    if (nextPacketClass.equals(factory.getTargetClass())) {
      nextPacket =
          PacketFactories.getFactory(Packet.class, NotApplicable.class)
              .newInstance(
                  rawData, payloadOffset, payloadLength, NotApplicable.UNKNOWN_IP_V6_EXTENSION);
      if (nextPacket instanceof IllegalPacket) {
        nextPacket = factory.newInstance(rawData, payloadOffset, payloadLength);
      }
    } else {
      nextPacket = factory.newInstance(rawData, payloadOffset, payloadLength, number);
    }

    this.payload = nextPacket;
  }

  /** @param builder builder */
  protected IpV6ExtOptionsPacket(Builder builder) {
    if (builder == null || builder.nextHeader == null || builder.options == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ")
          .append(builder)
          .append(" builder.nextHeader: ")
          .append(builder.nextHeader)
          .append(" builder.options: ")
          .append(builder.options);
      throw new NullPointerException(sb.toString());
    }
    //   if (builder.options.size() == 0) {
    //     throw new IllegalArgumentException(
    //             "No option is invalid to IPv6 Options Header"
    //           );
    //   }

    this.payload = builder.payloadBuilder != null ? builder.payloadBuilder.build() : null;
  }

  @Override
  public abstract IpV6ExtOptionsHeader getHeader();

  @Override
  public Packet getPayload() {
    return payload;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.10
   */
  public abstract static class Builder extends AbstractBuilder
      implements LengthBuilder<IpV6ExtOptionsPacket> {

    private IpNumber nextHeader;
    private byte hdrExtLen;
    private List<IpV6Option> options;
    private Packet.Builder payloadBuilder;
    private boolean correctLengthAtBuild;

    /** */
    public Builder() {}

    /** @param packet packet */
    protected Builder(IpV6ExtOptionsPacket packet) {
      this.nextHeader = packet.getHeader().nextHeader;
      this.hdrExtLen = packet.getHeader().hdrExtLen;
      this.options = packet.getHeader().options;
      this.payloadBuilder = packet.payload != null ? packet.payload.getBuilder() : null;
    }

    /**
     * @param nextHeader nextHeader
     * @return this Builder object for method chaining.
     */
    public Builder nextHeader(IpNumber nextHeader) {
      this.nextHeader = nextHeader;
      return this;
    }

    /**
     * @param hdrExtLen hdrExtLen
     * @return this Builder object for method chaining.
     */
    public Builder hdrExtLen(byte hdrExtLen) {
      this.hdrExtLen = hdrExtLen;
      return this;
    }

    /**
     * @param options options
     * @return this Builder object for method chaining.
     */
    public Builder options(List<IpV6Option> options) {
      this.options = options;
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
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.10
   */
  public abstract static class IpV6ExtOptionsHeader extends AbstractHeader {

    /*
     *  0                              16                            31
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |  Next Header  |  Hdr Ext Len  |                               |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
     * |                                                               |
     * .                                                               .
     * .                            Options                            .
     * .                                                               .
     * |                                                               |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *
     */

    /** */
    private static final long serialVersionUID = 224822728201337667L;

    private static final int NEXT_HEADER_OFFSET = 0;
    private static final int NEXT_HEADER_SIZE = BYTE_SIZE_IN_BYTES;
    private static final int HDR_EXT_LEN_OFFSET = NEXT_HEADER_OFFSET + NEXT_HEADER_SIZE;
    private static final int HDR_EXT_LEN_SIZE = BYTE_SIZE_IN_BYTES;
    private static final int OPTIONS_OFFSET = HDR_EXT_LEN_OFFSET + HDR_EXT_LEN_SIZE;

    private final IpNumber nextHeader;
    private final byte hdrExtLen;
    private final List<IpV6Option> options;

    /**
     * @param rawData rawData
     * @param offset offset
     * @param length length
     * @throws IllegalRawDataException if parsing the raw data fails.
     */
    protected IpV6ExtOptionsHeader(byte[] rawData, int offset, int length)
        throws IllegalRawDataException {
      if (length < 2) {
        StringBuilder sb = new StringBuilder(110);
        sb.append("The data length of ")
            .append(getHeaderName())
            .append(" is must be more than 1. data: ")
            .append(ByteArrays.toHexString(rawData, " "))
            .append(", offset: ")
            .append(offset)
            .append(", length: ")
            .append(length);
        throw new IllegalRawDataException(sb.toString());
      }

      this.nextHeader =
          IpNumber.getInstance(ByteArrays.getByte(rawData, NEXT_HEADER_OFFSET + offset));
      this.hdrExtLen = ByteArrays.getByte(rawData, HDR_EXT_LEN_OFFSET + offset);

      int headerLength = (getHdrExtLenAsInt() + 1) * 8;
      if (length < headerLength) {
        StringBuilder sb = new StringBuilder(110);
        sb.append("The data is too short to build an ")
            .append(getHeaderName())
            .append("(")
            .append(headerLength)
            .append(" bytes). data: ")
            .append(ByteArrays.toHexString(rawData, " "))
            .append(", offset: ")
            .append(offset)
            .append(", length: ")
            .append(length);
        throw new IllegalRawDataException(sb.toString());
      }

      this.options = new ArrayList<IpV6Option>();

      int currentOffsetInHeader = OPTIONS_OFFSET;
      while (currentOffsetInHeader < headerLength) {
        IpV6OptionType type = IpV6OptionType.getInstance(rawData[currentOffsetInHeader + offset]);
        IpV6Option newOne;
        try {
          newOne =
              PacketFactories.getFactory(IpV6Option.class, IpV6OptionType.class)
                  .newInstance(
                      rawData,
                      currentOffsetInHeader + offset,
                      headerLength - currentOffsetInHeader,
                      type);
        } catch (Exception e) {
          break;
        }

        options.add(newOne);
        currentOffsetInHeader += newOne.length();
      }
    }

    /** @param builder builder */
    protected IpV6ExtOptionsHeader(Builder builder) {
      int optLength = 0;
      for (IpV6Option o : builder.options) {
        optLength += o.length();
      }

      if ((optLength + 2) % 8 != 0) {
        StringBuilder sb = new StringBuilder(200);
        String ls = System.getProperty("line.separator");

        sb.append("options length is invalid.")
            .append(" ([options length] + 2) % 8 must be 0.")
            .append(" options: ")
            .append(ls);
        for (IpV6Option opt : builder.options) {
          sb.append(opt).append(ls);
        }
        throw new IllegalArgumentException(sb.toString());
      }

      this.nextHeader = builder.nextHeader;
      this.options = new ArrayList<IpV6Option>(builder.options);

      if (builder.correctLengthAtBuild) {
        this.hdrExtLen = (byte) ((optLength + 2) / 8 - 1);
      } else {
        this.hdrExtLen = builder.hdrExtLen;
      }
    }

    /** @return nextHeader */
    public IpNumber getNextHeader() {
      return nextHeader;
    }

    /** @return hdrExtLen */
    public byte getHdrExtLen() {
      return hdrExtLen;
    }

    /** @return hdrExtLen */
    public int getHdrExtLenAsInt() {
      return 0xFF & hdrExtLen;
    }

    /** @return options */
    public List<IpV6Option> getOptions() {
      return new ArrayList<IpV6Option>(options);
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(ByteArrays.toByteArray(nextHeader.value()));
      rawFields.add(ByteArrays.toByteArray(hdrExtLen));
      for (IpV6Option o : options) {
        rawFields.add(o.getRawData());
      }
      return rawFields;
    }

    @Override
    public int calcLength() {
      int optLength = 0;
      for (IpV6Option o : options) {
        optLength += o.length();
      }
      return optLength + 2;
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[")
          .append(getHeaderName())
          .append(" (")
          .append(length())
          .append(" bytes)]")
          .append(ls);
      sb.append("  Next Header: ").append(nextHeader).append(ls);
      sb.append("  Hdr Ext Len: ")
          .append(getHdrExtLenAsInt())
          .append(" (")
          .append((getHdrExtLenAsInt() + 1) * 8)
          .append(" [bytes])")
          .append(ls);
      sb.append("  Options: ").append(ls);
      for (IpV6Option opt : options) {
        sb.append("    ").append(opt).append(ls);
      }

      return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
      if (obj == this) {
        return true;
      }
      if (!this.getClass().isInstance(obj)) {
        return false;
      }

      IpV6ExtOptionsHeader other = (IpV6ExtOptionsHeader) obj;
      return nextHeader.equals(other.nextHeader)
          && hdrExtLen == other.hdrExtLen
          && options.equals(other.options);
    }

    @Override
    protected int calcHashCode() {
      int result = 17;
      result = 31 * result + nextHeader.hashCode();
      result = 31 * result + hdrExtLen;
      result = 31 * result + options.hashCode();
      return result;
    }

    /** @return header name */
    protected abstract String getHeaderName();
  }

  /**
   * The interface representing an IPv6 option. If you use {@link
   * org.pcap4j.packet.factory.propertiesbased.PropertiesBasedPacketFactory
   * PropertiesBasedPacketFactory}, classes which implement this interface must implement the
   * following method: {@code public static IpV6Option newInstance(byte[] rawData, int offset, int
   * length) throws IllegalRawDataException}
   *
   * @author Kaito Yamada
   * @since pcap4j 0.9.11
   */
  public interface IpV6Option extends Serializable {

    /** @return type */
    public IpV6OptionType getType();

    /** @return length */
    public int length();

    /** @return raw data */
    public byte[] getRawData();
  }
}
