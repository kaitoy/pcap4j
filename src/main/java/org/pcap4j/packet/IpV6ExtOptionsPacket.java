/*_##########################################################################
  _##
  _##  Copyright (C) 2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.util.ByteArrays;
import static org.pcap4j.util.ByteArrays.BYTE_SIZE_IN_BYTES;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.10
 */
public abstract class IpV6ExtOptionsPacket extends AbstractPacket {

  /**
   *
   */
  private static final long serialVersionUID = 2550533414788349771L;

  private final IpV6ExtOptionHeader header;
  private final Packet payload;

  protected IpV6ExtOptionsPacket(byte[] rawData) {
    this.header = new IpV6ExtOptionHeader(rawData);

    byte[] rawPayload
      = ByteArrays.getSubArray(
          rawData,
          header.length(),
          rawData.length - header.length()
        );

    this.payload
      = PacketFactories.getPacketFactory(IpNumber.class)
          .newPacket(rawPayload, header.getNextHeader());
  }

  protected IpV6ExtOptionsPacket(Builder builder) {
    if (
         builder == null
      || builder.nextHeader == null
      || builder.options == null
      || builder.payloadBuilder == null
    ) {
      throw new NullPointerException();
    }
    if (builder.options.size() == 0) {
      throw new IllegalArgumentException();
    }

    this.payload = builder.payloadBuilder.build();
    this.header = new IpV6ExtOptionHeader(builder);
  }

  @Override
  public IpV6ExtOptionHeader getHeader() {
    return header;
  }

  @Override
  public Packet getPayload() {
    return payload;
  }

  @Override
  protected boolean verify() {
    if (!(payload instanceof UdpPacket)) {
      if (!payload.isValid()) {
        return false;
      }
    }

    return header.isValid();
  }

  protected abstract String getExactOptionName();

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.10
   */
  public static abstract class Builder extends AbstractBuilder {

    private IpNumber nextHeader;
    private byte hdrExtLen;
    private List<IpV6Option> options;
    private Packet.Builder payloadBuilder;
    private boolean validateAtBuild = true;

    /**
     *
     */
    public Builder() {}

    /**
     *
     * @param packet
     */
    public Builder(IpV6ExtOptionsPacket packet) {
      this.nextHeader = packet.header.nextHeader;
      this.hdrExtLen = packet.header.hdrExtLen;
      this.options = packet.header.options;
      this.payloadBuilder = packet.payload.getBuilder();
    }

    /**
     *
     * @param nextHeader
     * @return
     */
    public Builder nextHeader(IpNumber nextHeader) {
      this.nextHeader = nextHeader;
      return this;
    }

    /**
     *
     * @param hdrExtLen
     * @return
     */
    public Builder hdrExtLen(byte hdrExtLen) {
      this.hdrExtLen = hdrExtLen;
      return this;
    }

    /**
     *
     * @param options
     * @return
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

    /**
     *
     * @param validateAtBuild
     * @return
     */
    public Builder validateAtBuild(boolean validateAtBuild) {
      this.validateAtBuild = validateAtBuild;
      return this;
    }

  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.10
   */
  public final class IpV6ExtOptionHeader extends AbstractHeader {

    /*
     * 0                               16                              32
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

    /**
     *
     */
    private static final long serialVersionUID = 224822728201337667L;

    private static final int NEXT_HEADER_OFFSET
      = 0;
    private static final int NEXT_HEADER_SIZE
      = BYTE_SIZE_IN_BYTES;
    private static final int HDR_EXT_LEN_OFFSET
      = NEXT_HEADER_OFFSET + NEXT_HEADER_SIZE;
    private static final int HDR_EXT_LEN_SIZE
      = BYTE_SIZE_IN_BYTES;
    private static final int OPTIONS_OFFSET
      = HDR_EXT_LEN_OFFSET + HDR_EXT_LEN_SIZE;

    private final IpNumber nextHeader;
    private final byte hdrExtLen;
    private final List<IpV6Option> options;

    private IpV6ExtOptionHeader(byte[] rawData) {
      if (rawData.length < 2) {
        StringBuilder sb = new StringBuilder(110);
        sb.append(
            "The data length of IPv6 option header is must be more than 1. data: "
           )
          .append(ByteArrays.toHexString(rawData, " "));
        throw new IllegalPacketDataException(sb.toString());
      }

      this.nextHeader
        = IpNumber
            .getInstance(ByteArrays.getByte(rawData, NEXT_HEADER_OFFSET));
      this.hdrExtLen
        = ByteArrays.getByte(rawData, HDR_EXT_LEN_OFFSET);

      int headerLength = (hdrExtLen & 0xFF + 1) * 8;
      if (rawData.length < headerLength) {
        StringBuilder sb = new StringBuilder(110);
        sb.append("The data is too short to build an IPv6 option header(")
          .append(headerLength)
          .append(" bytes). data: ")
          .append(ByteArrays.toHexString(rawData, " "));
        throw new IllegalPacketDataException(sb.toString());
      }

      this.options = new ArrayList<IpV6Option>();

      int currentOffset = OPTIONS_OFFSET;
      while (currentOffset < headerLength) {
        IpV6Option newOne = IpV6Option.newInstance(
                              ByteArrays.getSubArray(
                                rawData,
                                currentOffset,
                                headerLength - currentOffset
                              )
                            );
        options.add(newOne);
        currentOffset += newOne.length();
      }
    }

    private IpV6ExtOptionHeader(Builder builder) {
      int optLength = 0;
      for (IpV6Option o: builder.options) {
        optLength += o.length();
      }

      if ((optLength + 2) % 8 != 0) {
        StringBuilder sb = new StringBuilder(200);
        String ls = System.getProperty("line.separator");

        sb.append("options length is invalid.")
          .append(" ([options length] + 2) % 8 must be 0.")
          .append(" options: ")
          .append(ls);
        for (IpV6Option opt: builder.options) {
          sb.append(opt)
            .append(ls);
        }
        throw new IllegalArgumentException(sb.toString());
      }

      this.nextHeader = builder.nextHeader;
      this.options = new ArrayList<IpV6Option>(builder.options);

      if (builder.validateAtBuild) {
        this.hdrExtLen = (byte)((optLength + 2) / 8 - 1);
      }
      else {
        this.hdrExtLen = builder.hdrExtLen;
      }
    }

    /**
     *
     * @return
     */
    public IpNumber getNextHeader() {
      return nextHeader;
    }

    /**
     *
     * @return
     */
    public byte getHdrExtLen() {
      return hdrExtLen;
    }

    /**
     *
     * @return
     */
    public int getHdrExtLenAsInt() {
      return (int)(0xFF & hdrExtLen);
    }

    /**
     *
     * @return
     */
    public List<IpV6Option> getOptions() {
      return Collections.unmodifiableList(options);
    }

    @Override
    protected boolean verify() {
      return length() / 8 - 1 == getHdrExtLenAsInt();
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(ByteArrays.toByteArray(nextHeader.value()));
      rawFields.add(ByteArrays.toByteArray(hdrExtLen));
      for (IpV6Option o: options) {
        rawFields.add(o.getRawData());
      }
      return rawFields;
    }

    @Override
    public int measureLength() {
      int optLength = 0;
      for (IpV6Option o: options) {
        optLength += o.length();
      }
      return optLength + 2;
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[IPv6 ")
        .append(IpV6ExtOptionsPacket.this.getExactOptionName())
        .append(" Header (")
        .append(length())
        .append(" bytes)]")
        .append(ls);
      sb.append("  Next Header: ")
        .append(nextHeader)
        .append(ls);
      sb.append("  Hdr Ext Len: ")
        .append(getHdrExtLenAsInt())
        .append(" (")
        .append((getHdrExtLenAsInt() + 1) * 8)
        .append(" [bytes])")
        .append(ls);
      sb.append("  Options: ")
        .append(ls);
      for (IpV6Option opt: options) {
        sb.append("    ")
          .append(opt)
          .append(ls);
      }

      return sb.toString();
    }

  }

}
