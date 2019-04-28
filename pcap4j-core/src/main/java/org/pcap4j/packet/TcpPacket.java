/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.INT_SIZE_IN_BYTES;
import static org.pcap4j.util.ByteArrays.SHORT_SIZE_IN_BYTES;

import java.io.Serializable;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.factory.PacketFactory;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.TcpOptionKind;
import org.pcap4j.packet.namednumber.TcpPort;
import org.pcap4j.util.ByteArrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.12
 */
public final class TcpPacket extends AbstractPacket implements TransportPacket {

  // http://tools.ietf.org/html/rfc793

  /** */
  private static final long serialVersionUID = 7904566782140471299L;

  private final TcpHeader header;
  private final Packet payload;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new TcpPacket object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static TcpPacket newPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new TcpPacket(rawData, offset, length);
  }

  private TcpPacket(byte[] rawData, int offset, int length) throws IllegalRawDataException {
    this.header = new TcpHeader(rawData, offset, length);

    int payloadLength = length - header.length();
    if (payloadLength > 0) {
      PacketFactory<Packet, TcpPort> factory =
          PacketFactories.getFactory(Packet.class, TcpPort.class);
      Class<? extends Packet> class4UnknownPort = factory.getTargetClass();
      Class<? extends Packet> class4DstPort = factory.getTargetClass(header.getDstPort());
      TcpPort serverPort;
      if (class4DstPort.equals(class4UnknownPort)) {
        serverPort = header.getSrcPort();
      } else {
        serverPort = header.getDstPort();
      }
      this.payload =
          PacketFactories.getFactory(Packet.class, TcpPort.class)
              .newInstance(rawData, offset + header.length(), payloadLength, serverPort);
    } else {
      this.payload = null;
    }
  }

  private TcpPacket(Builder builder) {
    if (builder == null || builder.srcPort == null || builder.dstPort == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ")
          .append(builder)
          .append(" builder.srcPort: ")
          .append(builder.srcPort)
          .append(" builder.dstPort: ")
          .append(builder.dstPort);
      throw new NullPointerException(sb.toString());
    }

    if (builder.correctChecksumAtBuild) {
      if (builder.srcAddr == null || builder.dstAddr == null) {
        StringBuilder sb = new StringBuilder();
        sb.append("builder.srcAddr: ")
            .append(builder.srcAddr)
            .append(" builder.dstAddr: ")
            .append(builder.dstAddr);
        throw new NullPointerException(sb.toString());
      }
      if (!builder.srcAddr.getClass().isInstance(builder.dstAddr)) {
        StringBuilder sb = new StringBuilder();
        sb.append("builder.srcAddr: ")
            .append(builder.srcAddr)
            .append(" builder.dstAddr: ")
            .append(builder.dstAddr);
        throw new IllegalArgumentException(sb.toString());
      }
    }

    this.payload = builder.payloadBuilder != null ? builder.payloadBuilder.build() : null;
    this.header = new TcpHeader(builder, payload != null ? payload.getRawData() : new byte[0]);
  }

  @Override
  public TcpHeader getHeader() {
    return header;
  }

  @Override
  public Packet getPayload() {
    return payload;
  }

  /**
   * checksum verification is necessary for IPv6(i.e. acceptZero must be false)
   *
   * @param srcAddr srcAddr
   * @param dstAddr dstAddr
   * @param acceptZero acceptZero
   * @return true if the packet represented by this object has a valid checksum; false otherwise.
   */
  public boolean hasValidChecksum(InetAddress srcAddr, InetAddress dstAddr, boolean acceptZero) {
    if (srcAddr == null || dstAddr == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("srcAddr: ").append(srcAddr).append(" dstAddr: ").append(dstAddr);
      throw new NullPointerException(sb.toString());
    }
    if (!srcAddr.getClass().isInstance(dstAddr)) {
      StringBuilder sb = new StringBuilder();
      sb.append("srcAddr: ").append(srcAddr).append(" dstAddr: ").append(dstAddr);
      throw new IllegalArgumentException(sb.toString());
    }

    byte[] payloadData = payload != null ? payload.getRawData() : new byte[0];
    short calculatedChecksum =
        header.calcChecksum(srcAddr, dstAddr, header.getRawData(), payloadData);
    if (calculatedChecksum == 0) {
      return true;
    }

    if (header.checksum == 0 && acceptZero) {
      return true;
    }

    return false;
  }

  @Override
  public Builder getBuilder() {
    return new Builder(this);
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.12
   */
  public static final class Builder extends AbstractBuilder
      implements LengthBuilder<TcpPacket>, ChecksumBuilder<TcpPacket> {

    private TcpPort srcPort;
    private TcpPort dstPort;
    private int sequenceNumber;
    private int acknowledgmentNumber;
    private byte dataOffset;
    private byte reserved;
    private boolean urg;
    private boolean ack;
    private boolean psh;
    private boolean rst;
    private boolean syn;
    private boolean fin;
    private short window;
    private short checksum;
    private short urgentPointer;
    private List<TcpOption> options;
    private byte[] padding;
    private Packet.Builder payloadBuilder;
    private InetAddress srcAddr;
    private InetAddress dstAddr;
    private boolean correctLengthAtBuild;
    private boolean correctChecksumAtBuild;
    private boolean paddingAtBuild;

    /** */
    public Builder() {}

    /** @param packet packet */
    public Builder(TcpPacket packet) {
      this.srcPort = packet.header.srcPort;
      this.dstPort = packet.header.dstPort;
      this.sequenceNumber = packet.header.sequenceNumber;
      this.acknowledgmentNumber = packet.header.acknowledgmentNumber;
      this.dataOffset = packet.header.dataOffset;
      this.reserved = packet.header.reserved;
      this.urg = packet.header.urg;
      this.ack = packet.header.ack;
      this.psh = packet.header.psh;
      this.rst = packet.header.rst;
      this.syn = packet.header.syn;
      this.fin = packet.header.fin;
      this.window = packet.header.window;
      this.checksum = packet.header.checksum;
      this.urgentPointer = packet.header.urgentPointer;
      this.options = packet.header.options;
      this.padding = packet.header.padding;
      this.payloadBuilder = packet.payload != null ? packet.payload.getBuilder() : null;
    }

    /**
     * @param srcPort srcPort
     * @return this Builder object for method chaining.
     */
    public Builder srcPort(TcpPort srcPort) {
      this.srcPort = srcPort;
      return this;
    }

    /**
     * @param dstPort dstPort
     * @return this Builder object for method chaining.
     */
    public Builder dstPort(TcpPort dstPort) {
      this.dstPort = dstPort;
      return this;
    }

    /**
     * @param sequenceNumber sequenceNumber
     * @return this Builder object for method chaining.
     */
    public Builder sequenceNumber(int sequenceNumber) {
      this.sequenceNumber = sequenceNumber;
      return this;
    }

    /**
     * @param acknowledgmentNumber acknowledgmentNumber
     * @return this Builder object for method chaining.
     */
    public Builder acknowledgmentNumber(int acknowledgmentNumber) {
      this.acknowledgmentNumber = acknowledgmentNumber;
      return this;
    }

    /**
     * @param dataOffset dataOffset
     * @return this Builder object for method chaining.
     */
    public Builder dataOffset(byte dataOffset) {
      this.dataOffset = dataOffset;
      return this;
    }

    /**
     * @param reserved reserved
     * @return this Builder object for method chaining.
     */
    public Builder reserved(byte reserved) {
      this.reserved = reserved;
      return this;
    }

    /**
     * @param urg urg
     * @return this Builder object for method chaining.
     */
    public Builder urg(boolean urg) {
      this.urg = urg;
      return this;
    }

    /**
     * @param ack ack
     * @return this Builder object for method chaining.
     */
    public Builder ack(boolean ack) {
      this.ack = ack;
      return this;
    }

    /**
     * @param psh psh
     * @return this Builder object for method chaining.
     */
    public Builder psh(boolean psh) {
      this.psh = psh;
      return this;
    }

    /**
     * @param rst rst
     * @return this Builder object for method chaining.
     */
    public Builder rst(boolean rst) {
      this.rst = rst;
      return this;
    }

    /**
     * @param syn syn
     * @return this Builder object for method chaining.
     */
    public Builder syn(boolean syn) {
      this.syn = syn;
      return this;
    }

    /**
     * @param fin fin
     * @return this Builder object for method chaining.
     */
    public Builder fin(boolean fin) {
      this.fin = fin;
      return this;
    }

    /**
     * @param window window
     * @return this Builder object for method chaining.
     */
    public Builder window(short window) {
      this.window = window;
      return this;
    }

    /**
     * @param checksum checksum
     * @return this Builder object for method chaining.
     */
    public Builder checksum(short checksum) {
      this.checksum = checksum;
      return this;
    }

    /**
     * @param urgentPointer urgentPointer
     * @return this Builder object for method chaining.
     */
    public Builder urgentPointer(short urgentPointer) {
      this.urgentPointer = urgentPointer;
      return this;
    }

    /**
     * @param options options
     * @return this Builder object for method chaining.
     */
    public Builder options(List<TcpOption> options) {
      this.options = options;
      return this;
    }

    /**
     * @param padding padding
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

    /**
     * used for checksum calculation.
     *
     * @param srcAddr srcAddr
     * @return this Builder object for method chaining.
     */
    public Builder srcAddr(InetAddress srcAddr) {
      this.srcAddr = srcAddr;
      return this;
    }

    /**
     * used for checksum calculation If the lower-layer packet is a IPv6 packet and the extension
     * headers including a routing header, this parameter is that of the final destination. (i.e.
     * the last element of the Routing header)
     *
     * @param dstAddr dstAddr
     * @return this Builder object for method chaining.
     */
    public Builder dstAddr(InetAddress dstAddr) {
      this.dstAddr = dstAddr;
      return this;
    }

    @Override
    public Builder correctLengthAtBuild(boolean correctLengthAtBuild) {
      this.correctLengthAtBuild = correctLengthAtBuild;
      return this;
    }

    @Override
    public Builder correctChecksumAtBuild(boolean correctChecksumAtBuild) {
      this.correctChecksumAtBuild = correctChecksumAtBuild;
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

    @Override
    public TcpPacket build() {
      return new TcpPacket(this);
    }
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.12
   */
  public static final class TcpHeader extends AbstractHeader implements TransportHeader {

    /*
     *  0                              16                            31
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |          Source Port          |       Destination Port        |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                        Sequence Number                        |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                    Acknowledgment Number                      |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |  Data |           |U|A|P|R|S|F|                               |
     * | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
     * |       |           |G|K|H|T|N|N|                               |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |           Checksum            |         Urgent Pointer        |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                    Options                    |    Padding    |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */

    /*
     *                        IPv4 Pseudo Header
     *
     * 0                               16                            31
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                       Src IP Address                          |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                       Dst IP Address                          |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |      PAD      | Protocol(TCP) |            Length             |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *
     *                      IPv6 Pseudo Header
     *
     *  0                              16                            31
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                                                               |
     * +                                                               +
     * |                                                               |
     * +                         Source Address                        +
     * |                                                               |
     * +                                                               +
     * |                                                               |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                                                               |
     * +                                                               +
     * |                                                               |
     * +                      Destination Address                      +
     * |                                                               |
     * +                                                               +
     * |                                                               |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                   Upper-Layer Packet Length                   |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                      zero                     |  Next Header  |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */

    private static final Logger logger = LoggerFactory.getLogger(TcpHeader.class);
    /** */
    private static final long serialVersionUID = -795185420055823677L;

    private static final int SRC_PORT_OFFSET = 0;
    private static final int SRC_PORT_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int DST_PORT_OFFSET = SRC_PORT_OFFSET + SRC_PORT_SIZE;
    private static final int DST_PORT_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int SEQUENCE_NUMBER_OFFSET = DST_PORT_OFFSET + DST_PORT_SIZE;
    private static final int SEQUENCE_NUMBER_SIZE = INT_SIZE_IN_BYTES;
    private static final int ACKNOWLEDGMENT_NUMBER_OFFSET =
        SEQUENCE_NUMBER_OFFSET + SEQUENCE_NUMBER_SIZE;
    private static final int ACKNOWLEDGMENT_NUMBER_SIZE = INT_SIZE_IN_BYTES;
    private static final int DATA_OFFSET_AND_RESERVED_AND_CONTROL_BITS_OFFSET =
        ACKNOWLEDGMENT_NUMBER_OFFSET + ACKNOWLEDGMENT_NUMBER_SIZE;
    private static final int DATA_OFFSET_AND_RESERVED_AND_CONTROL_BITS_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int WINDOW_OFFSET =
        DATA_OFFSET_AND_RESERVED_AND_CONTROL_BITS_OFFSET
            + DATA_OFFSET_AND_RESERVED_AND_CONTROL_BITS_SIZE;
    private static final int WINDOW_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int CHECKSUM_OFFSET = WINDOW_OFFSET + WINDOW_SIZE;
    private static final int CHECKSUM_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int URGENT_POINTER_OFFSET = CHECKSUM_OFFSET + CHECKSUM_SIZE;
    private static final int URGENT_POINTER_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int OPTIONS_OFFSET = URGENT_POINTER_OFFSET + URGENT_POINTER_SIZE;

    private static final int MIN_TCP_HEADER_SIZE = URGENT_POINTER_OFFSET + URGENT_POINTER_SIZE;

    private static final int IPV4_PSEUDO_HEADER_SIZE = 12;
    private static final int IPV6_PSEUDO_HEADER_SIZE = 40;

    private final TcpPort srcPort;
    private final TcpPort dstPort;
    private final int sequenceNumber;
    private final int acknowledgmentNumber;
    private final byte dataOffset;
    private final byte reserved;
    private final boolean urg;
    private final boolean ack;
    private final boolean psh;
    private final boolean rst;
    private final boolean syn;
    private final boolean fin;
    private final short window;
    private final short checksum;
    private final short urgentPointer;
    private final List<TcpOption> options;
    private final byte[] padding;

    private TcpHeader(byte[] rawData, int offset, int length) throws IllegalRawDataException {
      if (length < MIN_TCP_HEADER_SIZE) {
        StringBuilder sb = new StringBuilder(80);
        sb.append("The data is too short to build this header(")
            .append(MIN_TCP_HEADER_SIZE)
            .append(" bytes). data: ")
            .append(ByteArrays.toHexString(rawData, " "))
            .append(", offset: ")
            .append(offset)
            .append(", length: ")
            .append(length);
        throw new IllegalRawDataException(sb.toString());
      }

      this.srcPort = TcpPort.getInstance(ByteArrays.getShort(rawData, SRC_PORT_OFFSET + offset));
      this.dstPort = TcpPort.getInstance(ByteArrays.getShort(rawData, DST_PORT_OFFSET + offset));
      this.sequenceNumber = ByteArrays.getInt(rawData, SEQUENCE_NUMBER_OFFSET + offset);
      this.acknowledgmentNumber = ByteArrays.getInt(rawData, ACKNOWLEDGMENT_NUMBER_OFFSET + offset);

      short dataOffsetAndReservedAndControlBits =
          ByteArrays.getShort(rawData, DATA_OFFSET_AND_RESERVED_AND_CONTROL_BITS_OFFSET + offset);

      this.dataOffset = (byte) ((dataOffsetAndReservedAndControlBits & 0xF000) >> 12);
      this.reserved = (byte) ((dataOffsetAndReservedAndControlBits & 0x0FC0) >> 6);
      this.urg = (dataOffsetAndReservedAndControlBits & 0x0020) != 0;
      this.ack = (dataOffsetAndReservedAndControlBits & 0x0010) != 0;
      this.psh = (dataOffsetAndReservedAndControlBits & 0x0008) != 0;
      this.rst = (dataOffsetAndReservedAndControlBits & 0x0004) != 0;
      this.syn = (dataOffsetAndReservedAndControlBits & 0x0002) != 0;
      this.fin = (dataOffsetAndReservedAndControlBits & 0x0001) != 0;

      this.window = ByteArrays.getShort(rawData, WINDOW_OFFSET + offset);
      this.checksum = ByteArrays.getShort(rawData, CHECKSUM_OFFSET + offset);
      this.urgentPointer = ByteArrays.getShort(rawData, URGENT_POINTER_OFFSET + offset);

      int headerLength = getDataOffsetAsInt() * 4;
      if (length < headerLength) {
        StringBuilder sb = new StringBuilder(110);
        sb.append("The data is too short to build this header(")
            .append(headerLength)
            .append(" bytes). data: ")
            .append(ByteArrays.toHexString(rawData, " "))
            .append(", offset: ")
            .append(offset)
            .append(", length: ")
            .append(length);
        throw new IllegalRawDataException(sb.toString());
      }
      if (headerLength < OPTIONS_OFFSET) {
        StringBuilder sb = new StringBuilder(100);
        sb.append("The data offset must be equal or more than ")
            .append(OPTIONS_OFFSET / 4)
            .append(", but it is: ")
            .append(getDataOffsetAsInt());
        throw new IllegalRawDataException(sb.toString());
      }

      this.options = new ArrayList<TcpOption>();
      int currentOffsetInHeader = OPTIONS_OFFSET;
      try {
        while (currentOffsetInHeader < headerLength) {
          TcpOptionKind kind = TcpOptionKind.getInstance(rawData[currentOffsetInHeader + offset]);
          TcpOption newOne;
          newOne =
              PacketFactories.getFactory(TcpOption.class, TcpOptionKind.class)
                  .newInstance(
                      rawData,
                      currentOffsetInHeader + offset,
                      headerLength - currentOffsetInHeader,
                      kind);

          options.add(newOne);
          currentOffsetInHeader += newOne.length();

          if (newOne.getKind().equals(TcpOptionKind.END_OF_OPTION_LIST)) {
            break;
          }
        }
      } catch (Exception e) {
        logger.error("Exception occurred during analyzing TCP options: ", e);
      }

      int paddingLength = headerLength - currentOffsetInHeader;
      if (paddingLength != 0) { // paddingLength is positive.
        this.padding =
            ByteArrays.getSubArray(rawData, currentOffsetInHeader + offset, paddingLength);
      } else {
        this.padding = new byte[0];
      }
    }

    private TcpHeader(Builder builder, byte[] payload) {
      if ((builder.reserved & 0xC0) != 0) {
        throw new IllegalArgumentException("Invalid reserved: " + builder.reserved);
      }

      this.srcPort = builder.srcPort;
      this.dstPort = builder.dstPort;
      this.sequenceNumber = builder.sequenceNumber;
      this.acknowledgmentNumber = builder.acknowledgmentNumber;
      this.reserved = builder.reserved;
      this.urg = builder.urg;
      this.ack = builder.ack;
      this.psh = builder.psh;
      this.rst = builder.rst;
      this.syn = builder.syn;
      this.fin = builder.fin;
      this.window = builder.window;
      this.urgentPointer = builder.urgentPointer;
      if (builder.options != null) {
        this.options = new ArrayList<TcpOption>(builder.options);
      } else {
        this.options = new ArrayList<TcpOption>(0);
      }

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
        this.dataOffset = (byte) (length() / 4);
      } else {
        if ((builder.dataOffset & 0xF0) != 0) {
          throw new IllegalArgumentException("Invalid dataOffset: " + builder.dataOffset);
        }
        this.dataOffset = builder.dataOffset;
      }

      if (builder.correctChecksumAtBuild) {
        if ((builder.srcAddr instanceof Inet4Address
                && PacketPropertiesLoader.getInstance().tcpV4CalcChecksum())
            || (builder.srcAddr instanceof Inet6Address
                && PacketPropertiesLoader.getInstance().tcpV6CalcChecksum())) {
          this.checksum =
              calcChecksum(builder.srcAddr, builder.dstAddr, buildRawData(true), payload);
        } else {
          this.checksum = (short) 0;
        }
      } else {
        this.checksum = builder.checksum;
      }
    }

    private short calcChecksum(
        InetAddress srcAddr, InetAddress dstAddr, byte[] header, byte[] payload) {
      byte[] data;
      int destPos;
      int totalLength = payload.length + length();
      boolean lowerLayerIsIpV4 = srcAddr instanceof Inet4Address;

      int pseudoHeaderSize = lowerLayerIsIpV4 ? IPV4_PSEUDO_HEADER_SIZE : IPV6_PSEUDO_HEADER_SIZE;

      if ((totalLength % 2) != 0) {
        data = new byte[totalLength + 1 + pseudoHeaderSize];
        destPos = totalLength + 1;
      } else {
        data = new byte[totalLength + pseudoHeaderSize];
        destPos = totalLength;
      }

      System.arraycopy(header, 0, data, 0, header.length);
      System.arraycopy(payload, 0, data, header.length, payload.length);

      // pseudo header
      System.arraycopy(srcAddr.getAddress(), 0, data, destPos, srcAddr.getAddress().length);
      destPos += srcAddr.getAddress().length;

      System.arraycopy(dstAddr.getAddress(), 0, data, destPos, dstAddr.getAddress().length);
      destPos += dstAddr.getAddress().length;

      if (lowerLayerIsIpV4) {
        // data[destPos] = (byte)0;
        destPos++;
      } else {
        destPos += 3;
      }

      data[destPos] = IpNumber.TCP.value();
      destPos++;

      System.arraycopy(
          ByteArrays.toByteArray((short) totalLength), 0, data, destPos, SHORT_SIZE_IN_BYTES);
      destPos += SHORT_SIZE_IN_BYTES;

      return ByteArrays.calcChecksum(data);
    }

    @Override
    public TcpPort getSrcPort() {
      return srcPort;
    }

    @Override
    public TcpPort getDstPort() {
      return dstPort;
    }

    /** @return sequenceNumber */
    public int getSequenceNumber() {
      return sequenceNumber;
    }

    /** @return sequenceNumber */
    public long getSequenceNumberAsLong() {
      return sequenceNumber & 0xFFFFFFFFL;
    }

    /** @return acknowledgmentNumber */
    public int getAcknowledgmentNumber() {
      return acknowledgmentNumber;
    }

    /** @return acknowledgmentNumber */
    public long getAcknowledgmentNumberAsLong() {
      return acknowledgmentNumber & 0xFFFFFFFFL;
    }

    /** @return dataOffset */
    public byte getDataOffset() {
      return dataOffset;
    }

    /** @return dataOffset */
    public int getDataOffsetAsInt() {
      return 0xFF & dataOffset;
    }

    /** @return reserved */
    public byte getReserved() {
      return reserved;
    }

    /** @return urg */
    public boolean getUrg() {
      return urg;
    }

    /** @return ack */
    public boolean getAck() {
      return ack;
    }

    /** @return psh */
    public boolean getPsh() {
      return psh;
    }

    /** @return rst */
    public boolean getRst() {
      return rst;
    }

    /** @return syn */
    public boolean getSyn() {
      return syn;
    }

    /** @return fin */
    public boolean getFin() {
      return fin;
    }

    /** @return window */
    public short getWindow() {
      return window;
    }

    /** @return window */
    public int getWindowAsInt() {
      return 0xFFFF & window;
    }

    /** @return checksum */
    public short getChecksum() {
      return checksum;
    }

    /** @return urgentPointer */
    public short getUrgentPointer() {
      return urgentPointer;
    }

    /** @return urgentPointer */
    public int getUrgentPointerAsInt() {
      return urgentPointer & 0xFFFF;
    }

    /** @return options */
    public List<TcpOption> getOptions() {
      return new ArrayList<TcpOption>(options);
    }

    /** @return padding */
    public byte[] getPadding() {
      byte[] copy = new byte[padding.length];
      System.arraycopy(padding, 0, copy, 0, padding.length);
      return copy;
    }

    @Override
    protected List<byte[]> getRawFields() {
      return getRawFields(false);
    }

    private List<byte[]> getRawFields(boolean zeroInsteadOfChecksum) {
      byte flags = 0;
      if (fin) {
        flags = (byte) 1;
      }
      if (syn) {
        flags = (byte) (flags | 2);
      }
      if (rst) {
        flags = (byte) (flags | 4);
      }
      if (psh) {
        flags = (byte) (flags | 8);
      }
      if (ack) {
        flags = (byte) (flags | 16);
      }
      if (urg) {
        flags = (byte) (flags | 32);
      }

      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(ByteArrays.toByteArray(srcPort.value()));
      rawFields.add(ByteArrays.toByteArray(dstPort.value()));
      rawFields.add(ByteArrays.toByteArray(sequenceNumber));
      rawFields.add(ByteArrays.toByteArray(acknowledgmentNumber));
      rawFields.add(ByteArrays.toByteArray((short) ((dataOffset << 12) | (reserved << 6) | flags)));
      rawFields.add(ByteArrays.toByteArray(window));
      rawFields.add(ByteArrays.toByteArray(zeroInsteadOfChecksum ? (short) 0 : checksum));
      rawFields.add(ByteArrays.toByteArray(urgentPointer));
      for (TcpOption o : options) {
        rawFields.add(o.getRawData());
      }
      rawFields.add(padding);
      return rawFields;
    }

    private byte[] buildRawData(boolean zeroInsteadOfChecksum) {
      return ByteArrays.concatenate(getRawFields(zeroInsteadOfChecksum));
    }

    private int measureLengthWithoutPadding() {
      int len = 0;
      for (TcpOption o : options) {
        len += o.length();
      }
      return len + MIN_TCP_HEADER_SIZE;
    }

    @Override
    protected int calcLength() {
      return measureLengthWithoutPadding() + padding.length;
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[TCP Header (").append(length()).append(" bytes)]").append(ls);
      sb.append("  Source port: ").append(getSrcPort()).append(ls);
      sb.append("  Destination port: ").append(getDstPort()).append(ls);
      sb.append("  Sequence Number: ").append(getSequenceNumberAsLong()).append(ls);
      sb.append("  Acknowledgment Number: ").append(getAcknowledgmentNumberAsLong()).append(ls);
      sb.append("  Data Offset: ")
          .append(dataOffset)
          .append(" (")
          .append(dataOffset * 4)
          .append(" [bytes])")
          .append(ls);
      sb.append("  Reserved: ").append(reserved).append(ls);
      sb.append("  URG: ").append(urg).append(ls);
      sb.append("  ACK: ").append(ack).append(ls);
      sb.append("  PSH: ").append(psh).append(ls);
      sb.append("  RST: ").append(rst).append(ls);
      sb.append("  SYN: ").append(syn).append(ls);
      sb.append("  FIN: ").append(fin).append(ls);
      sb.append("  Window: ").append(getWindowAsInt()).append(ls);
      sb.append("  Checksum: 0x").append(ByteArrays.toHexString(checksum, "")).append(ls);
      sb.append("  Urgent Pointer: ").append(getUrgentPointerAsInt()).append(ls);
      for (TcpOption opt : options) {
        sb.append("  Option: ").append(opt).append(ls);
      }
      if (padding.length != 0) {
        sb.append("  Padding: 0x").append(ByteArrays.toHexString(padding, " ")).append(ls);
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

      TcpHeader other = (TcpHeader) obj;
      return checksum == other.checksum
          && sequenceNumber == other.sequenceNumber
          && acknowledgmentNumber == other.acknowledgmentNumber
          && dataOffset == other.dataOffset
          && srcPort.equals(other.srcPort)
          && dstPort.equals(other.dstPort)
          && urg == other.urg
          && ack == other.ack
          && psh == other.psh
          && rst == other.rst
          && syn == other.syn
          && fin == other.fin
          && window == other.window
          && urgentPointer == other.urgentPointer
          && reserved == other.reserved
          && options.equals(other.options)
          && Arrays.equals(padding, other.padding);
    }

    @Override
    protected int calcHashCode() {
      int result = 17;
      result = 31 * result + srcPort.hashCode();
      result = 31 * result + dstPort.hashCode();
      result = 31 * result + sequenceNumber;
      result = 31 * result + acknowledgmentNumber;
      result = 31 * result + dataOffset;
      result = 31 * result + reserved;
      result = 31 * result + (urg ? 1231 : 1237);
      result = 31 * result + (ack ? 1231 : 1237);
      result = 31 * result + (psh ? 1231 : 1237);
      result = 31 * result + (rst ? 1231 : 1237);
      result = 31 * result + (syn ? 1231 : 1237);
      result = 31 * result + (fin ? 1231 : 1237);
      result = 31 * result + window;
      result = 31 * result + checksum;
      result = 31 * result + urgentPointer;
      result = 31 * result + options.hashCode();
      result = 31 * result + Arrays.hashCode(padding);
      return result;
    }
  }

  /**
   * The interface representing a TCP option. If you use {@link
   * org.pcap4j.packet.factory.propertiesbased.PropertiesBasedPacketFactory
   * PropertiesBasedPacketFactory}, classes which implement this interface must implement the
   * following method: {@code public static TcpOption newInstance(byte[] rawData, int offset, int
   * length) throws IllegalRawDataException}
   *
   * @author Kaito Yamada
   * @since pcap4j 0.9.12
   */
  public interface TcpOption extends Serializable {

    /** @return kind */
    public TcpOptionKind getKind();

    /** @return length */
    public int length();

    /** @return raw data */
    public byte[] getRawData();
  }
}
