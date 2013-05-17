/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.*;
import java.io.Serializable;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import org.pcap4j.packet.factory.ClassifiedDataFactories;
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.TcpOptionKind;
import org.pcap4j.packet.namednumber.TcpPort;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.12
 */
public final class TcpPacket extends AbstractPacket {

  // http://tools.ietf.org/html/rfc793

  /**
   *
   */
  private static final long serialVersionUID = 7904566782140471299L;

  private final TcpHeader header;
  private final Packet payload;

  /**
   *
   * @param rawData
   * @return a new TcpPacket object.
   */
  public static TcpPacket newPacket(byte[] rawData) {
    return new TcpPacket(rawData);
  }

  private TcpPacket(byte[] rawData) {
    this.header = new TcpHeader(rawData);

    byte[] rawPayload
      = ByteArrays.getSubArray(
          rawData,
          header.length(),
          rawData.length - header.length()
        );

    this.payload
      = PacketFactories.getFactory(TcpPort.class)
          .newPacket(rawPayload, header.getDstPort());
  }

  private TcpPacket(Builder builder) {
    if (
         builder == null
      || builder.srcPort == null
      || builder.dstPort == null
      || builder.payloadBuilder == null
    ) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ").append(builder)
        .append(" builder.srcPort: ").append(builder.srcPort)
        .append(" builder.dstPort: ").append(builder.dstPort)
        .append(" builder.payloadBuilder: ").append(builder.payloadBuilder);
      throw new NullPointerException(sb.toString());
    }

    if (builder.correctChecksumAtBuild) {
      if (builder.srcAddr == null || builder.dstAddr == null) {
        StringBuilder sb = new StringBuilder();
        sb.append("builder.srcAddr: ").append(builder.srcAddr)
          .append(" builder.dstAddr: ").append(builder.dstAddr);
        throw new NullPointerException(sb.toString());
      }
      if (!builder.srcAddr.getClass().isInstance(builder.dstAddr)) {
        StringBuilder sb = new StringBuilder();
        sb.append("builder.srcAddr: ").append(builder.srcAddr)
          .append(" builder.dstAddr: ").append(builder.dstAddr);
        throw new IllegalArgumentException(sb.toString());
      }
    }

    this.payload = builder.payloadBuilder.build();
    this.header = new TcpHeader(
                    builder,
                    payload.getRawData()
                  );
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
   *
   * checksum varification is necessary for IPv6(i.e. acceptZero must be false)
   *
   * @param srcAddr
   * @param dstAddr
   * @param acceptZero
   * @return true if the packet represented by this object has a valid checksum;
   *         false otherwise.
   */
  public boolean hasValidChecksum(
    InetAddress srcAddr, InetAddress dstAddr, boolean acceptZero
  ) {
    if (srcAddr == null || dstAddr == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("srcAddr: ").append(srcAddr)
        .append(" dstAddr: ").append(dstAddr);
      throw new NullPointerException(sb.toString());
    }
    if (!srcAddr.getClass().isInstance(dstAddr)) {
      StringBuilder sb = new StringBuilder();
      sb.append("srcAddr: ").append(srcAddr)
        .append(" dstAddr: ").append(dstAddr);
      throw new IllegalArgumentException(sb.toString());
    }

    if (header.checksum == 0) {
      if (acceptZero) { return true; }
      else { return false; }
    }
    return header.calcChecksum(srcAddr, dstAddr, payload.getRawData())
             == header.checksum;
  }

  @Override
  public Builder getBuilder() {
    return new Builder(this);
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.12
   */
  public static final
  class Builder extends AbstractBuilder
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

    /**
     *
     */
    public Builder() {}

    /**
     *
     * @param packet
     */
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
      this.payloadBuilder = packet.payload.getBuilder();
    }

    /**
     *
     * @param srcPort
     * @return this Builder object for method chaining.
     */
    public Builder srcPort(TcpPort srcPort) {
      this.srcPort = srcPort;
      return this;
    }

    /**
     *
     * @param dstPort
     * @return this Builder object for method chaining.
     */
    public Builder dstPort(TcpPort dstPort) {
      this.dstPort = dstPort;
      return this;
    }

    /**
     *
     * @param sequenceNumber
     * @return this Builder object for method chaining.
     */
    public Builder sequenceNumber(int sequenceNumber) {
      this.sequenceNumber = sequenceNumber;
      return this;
    }

    /**
     *
     * @param acknowledgmentNumber
     * @return this Builder object for method chaining.
     */
    public Builder acknowledgmentNumber(int acknowledgmentNumber) {
      this.acknowledgmentNumber = acknowledgmentNumber;
      return this;
    }

    /**
     *
     * @param dataOffset
     * @return this Builder object for method chaining.
     */
    public Builder dataOffset(byte dataOffset) {
      this.dataOffset = dataOffset;
      return this;
    }

    /**
     *
     * @param reserved
     * @return this Builder object for method chaining.
     */
    public Builder reserved(byte reserved) {
      this.reserved = reserved;
      return this;
    }

    /**
     *
     * @param urg
     * @return this Builder object for method chaining.
     */
    public Builder urg(boolean urg) {
      this.urg = urg;
      return this;
    }

    /**
     *
     * @param ack
     * @return this Builder object for method chaining.
     */
    public Builder ack(boolean ack) {
      this.ack = ack;
      return this;
    }

    /**
     *
     * @param psh
     * @return this Builder object for method chaining.
     */
    public Builder psh(boolean psh) {
      this.psh = psh;
      return this;
    }

    /**
     *
     * @param rst
     * @return this Builder object for method chaining.
     */
    public Builder rst(boolean rst) {
      this.rst = rst;
      return this;
    }

    /**
     *
     * @param syn
     * @return this Builder object for method chaining.
     */
    public Builder syn(boolean syn) {
      this.syn = syn;
      return this;
    }

    /**
     *
     * @param fin
     * @return this Builder object for method chaining.
     */
    public Builder fin(boolean fin) {
      this.fin = fin;
      return this;
    }

    /**
     *
     * @param window
     * @return this Builder object for method chaining.
     */
    public Builder window(short window) {
      this.window = window;
      return this;
    }

    /**
     *
     * @param checksum
     * @return this Builder object for method chaining.
     */
    public Builder checksum(short checksum) {
      this.checksum = checksum;
      return this;
    }

    /**
     *
     * @param urgentPointer
     * @return this Builder object for method chaining.
     */
    public Builder urgentPointer(short urgentPointer) {
      this.urgentPointer = urgentPointer;
      return this;
    }

    /**
     *
     * @param options
     * @return this Builder object for method chaining.
     */
    public Builder options(List<TcpOption> options) {
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

    /**
     *
     * used for checksum calculation.
     *
     * @param srcAddr
     * @return this Builder object for method chaining.
     */
    public Builder srcAddr(InetAddress srcAddr) {
      this.srcAddr = srcAddr;
      return this;
    }

    /**
     *
     * used for checksum calculation
     * If the lower-layer packet is a IPv6 packet and
     * the extention headers including a routing header,
     * this parameter is that of the final destination.
     * (i.e. the last element of the Routing header)
     *
     * @param dstAddr
     * @return this Builder object for method chaining.
     */
    public Builder dstAddr(InetAddress dstAddr) {
      this.dstAddr = dstAddr;
      return this;
    }

    public Builder correctLengthAtBuild(boolean correctLengthAtBuild) {
      this.correctLengthAtBuild = correctLengthAtBuild;
      return this;
    }

    public Builder correctChecksumAtBuild(boolean correctChecksumAtBuild) {
      this.correctChecksumAtBuild = correctChecksumAtBuild;
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
    public TcpPacket build() {
      return new TcpPacket(this);
    }

  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.12
   */
  public static final class TcpHeader extends AbstractHeader {

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


    /**
     *
     */
    private static final long serialVersionUID = -795185420055823677L;

    private static final int SRC_PORT_OFFSET
      = 0;
    private static final int SRC_PORT_SIZE
      = SHORT_SIZE_IN_BYTES;
    private static final int DST_PORT_OFFSET
      = SRC_PORT_OFFSET + SRC_PORT_SIZE;
    private static final int DST_PORT_SIZE
      = SHORT_SIZE_IN_BYTES;
    private static final int SEQUENCE_NUMBER_OFFSET
      = DST_PORT_OFFSET + DST_PORT_SIZE;
    private static final int SEQUENCE_NUMBER_SIZE
      = INT_SIZE_IN_BYTES;
    private static final int ACKNOWLEDGMENT_NUMBER_OFFSET
      = SEQUENCE_NUMBER_OFFSET + SEQUENCE_NUMBER_SIZE;
    private static final int ACKNOWLEDGMENT_NUMBER_SIZE
      = INT_SIZE_IN_BYTES;
    private static final int DATA_OFFSET_AND_RESERVED_AND_CONTROL_BITS_OFFSET
      = ACKNOWLEDGMENT_NUMBER_OFFSET + ACKNOWLEDGMENT_NUMBER_SIZE;
    private static final int DATA_OFFSET_AND_RESERVED_AND_CONTROL_BITS_SIZE
      = SHORT_SIZE_IN_BYTES;
    private static final int WINDOW_OFFSET
     = DATA_OFFSET_AND_RESERVED_AND_CONTROL_BITS_OFFSET
         + DATA_OFFSET_AND_RESERVED_AND_CONTROL_BITS_SIZE;
    private static final int WINDOW_SIZE
      = SHORT_SIZE_IN_BYTES;
    private static final int CHECKSUM_OFFSET
      = WINDOW_OFFSET + WINDOW_SIZE;
    private static final int CHECKSUM_SIZE
      = SHORT_SIZE_IN_BYTES;
    private static final int URGENT_POINTER_OFFSET
      = CHECKSUM_OFFSET + CHECKSUM_SIZE;
    private static final int URGENT_POINTER_SIZE
      = SHORT_SIZE_IN_BYTES;
    private static final int OPTIONS_OFFSET
      = URGENT_POINTER_OFFSET + URGENT_POINTER_SIZE;

    private static final int MIN_TCP_HEADER_SIZE
      = URGENT_POINTER_OFFSET + URGENT_POINTER_SIZE;

    private static final int IP_V4_PSEUDO_HEADER_SIZE = 12;
    private static final int IP_V6_PSEUDO_HEADER_SIZE = 40;

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

    private TcpHeader(byte[] rawData) {
      if (rawData.length < MIN_TCP_HEADER_SIZE) {
        StringBuilder sb = new StringBuilder(80);
        sb.append("The data is too short to build this header(")
          .append(MIN_TCP_HEADER_SIZE)
          .append(" bytes). data: ")
          .append(ByteArrays.toHexString(rawData, " "));
        throw new IllegalRawDataException(sb.toString());
      }

      this.srcPort
        = TcpPort.getInstance(ByteArrays.getShort(rawData, SRC_PORT_OFFSET));
      this.dstPort
        = TcpPort.getInstance(ByteArrays.getShort(rawData, DST_PORT_OFFSET));
      this.sequenceNumber = ByteArrays.getInt(rawData, SEQUENCE_NUMBER_OFFSET);
      this.acknowledgmentNumber = ByteArrays.getInt(rawData, ACKNOWLEDGMENT_NUMBER_OFFSET);

      short dataOffsetAndReservedAndControlBits
        = ByteArrays.getShort(rawData, DATA_OFFSET_AND_RESERVED_AND_CONTROL_BITS_OFFSET);

      this.dataOffset = (byte)((dataOffsetAndReservedAndControlBits & 0xF000) >> 12);
      this.reserved = (byte)((dataOffsetAndReservedAndControlBits & 0x0FC0) >> 6);
      this.urg = (dataOffsetAndReservedAndControlBits & 0x0020) != 0;
      this.ack = (dataOffsetAndReservedAndControlBits & 0x0010) != 0;
      this.psh = (dataOffsetAndReservedAndControlBits & 0x0008) != 0;
      this.rst = (dataOffsetAndReservedAndControlBits & 0x0004) != 0;
      this.syn = (dataOffsetAndReservedAndControlBits & 0x0002) != 0;
      this.fin = (dataOffsetAndReservedAndControlBits & 0x0001) != 0;

      this.window = ByteArrays.getShort(rawData, WINDOW_OFFSET);
      this.checksum = ByteArrays.getShort(rawData, CHECKSUM_OFFSET);
      this.urgentPointer = ByteArrays.getShort(rawData, URGENT_POINTER_OFFSET);

      int headerLength = dataOffset * 4;
      if (rawData.length < headerLength) {
        StringBuilder sb = new StringBuilder(110);
        sb.append("The data is too short to build this header(")
          .append(headerLength)
          .append(" bytes). data: ")
          .append(ByteArrays.toHexString(rawData, " "));
        throw new IllegalRawDataException(sb.toString());
      }

      this.options = new ArrayList<TcpOption>();
      int currentOffset = OPTIONS_OFFSET;
      while (currentOffset < headerLength) {
        byte[] optRawData = ByteArrays.getSubArray(
                              rawData,
                              currentOffset,
                              headerLength - currentOffset
                            );
        TcpOptionKind kind = TcpOptionKind.getInstance(optRawData[0]);
        TcpOption newOne
          = ClassifiedDataFactories
              .getFactory(TcpOption.class, TcpOptionKind.class)
                 .newData(optRawData, kind);
        options.add(newOne);
        currentOffset += newOne.length();

        if (newOne.getKind().equals(TcpOptionKind.END_OF_OPTION_LIST)) {
          break;
        }
      }

      this.padding
        = ByteArrays.getSubArray(
            rawData, currentOffset, headerLength - currentOffset
          );
    }

    private TcpHeader(Builder builder, byte[] payload) {
      if ((builder.reserved & 0xC0) != 0) {
        throw new IllegalArgumentException(
                "Invalid reserved: " + builder.reserved
              );
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
      }
      else {
        this.options = new ArrayList<TcpOption>(0);
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
        this.dataOffset = (byte)(length() / 4);
      }
      else {
        if ((builder.dataOffset & 0xF0) != 0) {
          throw new IllegalArgumentException(
                  "Invalid dataOffset: " + builder.dataOffset
                );
        }
        this.dataOffset = builder.dataOffset;
      }

      if (builder.correctChecksumAtBuild) {
        if (
          (
            builder.srcAddr instanceof Inet4Address
              && PacketPropertiesLoader.getInstance().tcpV4CalcChecksum()
          )
          ||
          (
            builder.srcAddr instanceof Inet6Address
              && PacketPropertiesLoader.getInstance().tcpV6CalcChecksum()
          )
        ) {
          this.checksum = calcChecksum(builder.srcAddr, builder.dstAddr, payload);
        }
        else {
          this.checksum = (short)0;
        }
      }
      else {
        this.checksum = builder.checksum;
      }
    }

    private short calcChecksum(
      InetAddress srcAddr, InetAddress dstAddr, byte[] payload
    ) {
      byte[] data;
      int destPos;
      int totalLength = payload.length + length();
      boolean lowerLayerIsIpV4 = srcAddr instanceof Inet4Address;

      int pseudoHeaderSize
        = lowerLayerIsIpV4 ? IP_V4_PSEUDO_HEADER_SIZE
                           : IP_V6_PSEUDO_HEADER_SIZE;

      if ((totalLength % 2) != 0) {
        data = new byte[totalLength + 1 + pseudoHeaderSize];
        destPos = totalLength + 1;
      }
      else {
        data = new byte[totalLength + pseudoHeaderSize];
        destPos = totalLength;
      }

      // getRawData()だとchecksum field設定前にrawDataがキャッシュされてしまう場合があるので、
      // 代わりにbuildRawData()を使う。
      System.arraycopy(buildRawData(), 0, data, 0, length());
      System.arraycopy(payload, 0, data, length(), payload.length);

      for (int i = 0; i < CHECKSUM_SIZE; i++) {
        data[CHECKSUM_OFFSET + i] = (byte)0;
      }

      // pseudo header
      System.arraycopy(
        srcAddr.getAddress(), 0,
        data, destPos, srcAddr.getAddress().length
      );
      destPos += srcAddr.getAddress().length;

      System.arraycopy(
        dstAddr.getAddress(), 0,
        data, destPos, dstAddr.getAddress().length
      );
      destPos += dstAddr.getAddress().length;

      if (lowerLayerIsIpV4) {
        //data[destPos] = (byte)0;
        destPos++;
      }
      else {
        destPos += 3;
      }

      data[destPos] = IpNumber.TCP.value();
      destPos++;

      System.arraycopy(
        ByteArrays.toByteArray((short)totalLength), 0,
        data, destPos, SHORT_SIZE_IN_BYTES
      );
      destPos += SHORT_SIZE_IN_BYTES;

      return ByteArrays.calcChecksum(data);
    }

    /**
     *
     * @return srcPort
     */
    public TcpPort getSrcPort() { return srcPort; }

    /**
     *
     * @return dstPort
     */
    public TcpPort getDstPort() { return dstPort; }

    /**
     * @return sequenceNumber
     */
    public int getSequenceNumber() { return sequenceNumber; }

    /**
     *
     * @return sequenceNumber
     */
    public long getSequenceNumberAsLong() {
      return sequenceNumber & 0xFFFFFFFFL;
    }

    /**
     * @return acknowledgmentNumber
     */
    public int getAcknowledgmentNumber() { return acknowledgmentNumber; }

    /**
     *
     * @return acknowledgmentNumber
     */
    public long getAcknowledgmentNumberAsLong() {
      return acknowledgmentNumber & 0xFFFFFFFFL;
    }

    /**
     * @return dataOffset
     */
    public byte getDataOffset() { return dataOffset; }

    /**
     * @return reserved
     */
    public byte getReserved() { return reserved; }

    /**
     * @return urg
     */
    public boolean getUrg() { return urg; }

    /**
     * @return ack
     */
    public boolean getAck() { return ack; }

    /**
     * @return psh
     */
    public boolean getPsh() { return psh; }

    /**
     * @return rst
     */
    public boolean getRst() { return rst; }

    /**
     * @return syn
     */
    public boolean getSyn() { return syn; }

    /**
     * @return fin
     */
    public boolean getFin() { return fin; }

    /**
     * @return window
     */
    public short getWindow() { return window; }

    /**
     *
     * @return window
     */
    public int getWindowAsInt() { return 0xFFFF & window; }

    /**
     * @return checksum
     */
    public short getChecksum() { return checksum; }

    /**
     * @return urgentPointer
     */
    public short getUrgentPointer() { return urgentPointer; }

    /**
     *
     * @return urgentPointer
     */
    public int getUrgentPointerAsInt() { return urgentPointer & 0xFFFF; }

    /**
     * @return options
     */
    public List<TcpOption> getOptions() {
      return new ArrayList<TcpOption>(options);
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

    @Override
    protected List<byte[]> getRawFields() {
      byte flags = 0;
      if (fin) { flags = (byte)1; }
      if (syn) { flags = (byte)(flags | 2); }
      if (rst) { flags = (byte)(flags | 4); }
      if (psh) { flags = (byte)(flags | 8); }
      if (ack) { flags = (byte)(flags | 16); }
      if (urg) { flags = (byte)(flags | 32); }

      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(ByteArrays.toByteArray(srcPort.value()));
      rawFields.add(ByteArrays.toByteArray(dstPort.value()));
      rawFields.add(ByteArrays.toByteArray(sequenceNumber));
      rawFields.add(ByteArrays.toByteArray(acknowledgmentNumber));
      rawFields.add(
        ByteArrays.toByteArray(
          (short)(
              (dataOffset << 12)
            | (reserved << 6)
            | flags
          )
        )
      );
      rawFields.add(ByteArrays.toByteArray(window));
      rawFields.add(ByteArrays.toByteArray(checksum));
      rawFields.add(ByteArrays.toByteArray(urgentPointer));
      for (TcpOption o: options) {
        rawFields.add(o.getRawData());
      }
      rawFields.add(padding);
      return rawFields;
    }

    private int measureLengthWithoutPadding() {
      int len = 0;
      for (TcpOption o: options) {
        len += o.length();
      }
      return len + MIN_TCP_HEADER_SIZE;
    }

    @Override
    protected int measureLength() {
      return measureLengthWithoutPadding() + padding.length;
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[TCP Header (")
        .append(length())
        .append(" bytes)]")
        .append(ls);
      sb.append("  Source port: ")
        .append(getSrcPort())
        .append(ls);
      sb.append("  Destination port: ")
        .append(getDstPort())
        .append(ls);
      sb.append("  Sequence Number: ")
        .append(getSequenceNumberAsLong())
        .append(ls);
      sb.append("  Acknowledgment Number: ")
        .append(getAcknowledgmentNumberAsLong())
        .append(ls);
      sb.append("  Data Offset: ")
        .append(dataOffset)
        .append(" (")
        .append(dataOffset * 4)
        .append(" [bytes])")
        .append(ls);
      sb.append("  Reserved: ")
        .append(reserved)
        .append(ls);
      sb.append("  URG: ")
        .append(urg)
        .append(ls);
      sb.append("  ACK: ")
        .append(ack)
        .append(ls);
      sb.append("  PSH: ")
        .append(psh)
        .append(ls);
      sb.append("  RST: ")
        .append(rst)
        .append(ls);
      sb.append("  SYN: ")
        .append(syn)
        .append(ls);
      sb.append("  FIN: ")
        .append(fin)
        .append(ls);
      sb.append("  Window: ")
        .append(getWindowAsInt())
        .append(ls);
      sb.append("  Checksum: 0x")
        .append(ByteArrays.toHexString(checksum, ""))
        .append(ls);
      sb.append("  Urgent Pointer: ")
        .append(getUrgentPointerAsInt())
        .append(ls);
      for (TcpOption opt: options) {
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
   * @since pcap4j 0.9.12
   */
  public interface TcpOption extends Serializable {

    // /* must implement if use PropertiesBasedTcpOptionFactory */
    // public static TcpOption newInstance(byte[] rawData);

    /**
     *
     * @return kind
     */
    public TcpOptionKind getKind();

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

}
