/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.*;

import java.util.ArrayList;
import java.util.List;

import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.namednumber.SctpPort;
import org.pcap4j.util.ByteArrays;

/**
 * @author Jeff Myers (myersj@gmail.com)
 * @since pcap4j 1.6.6
 */
public final class SctpPacket extends AbstractPacket {

  /**
   *
   */
  private static final long serialVersionUID = -1082956644945517426L;

  private final SctpHeader header;
  private final Packet payload;

  /**
   * A static factory method.
   * This method validates the arguments by {@link ByteArrays#validateBounds(byte[], int, int)},
   * which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new SctpPacket object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static SctpPacket newPacket(
    byte[] rawData, int offset, int length
  ) throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new SctpPacket(rawData, offset, length);
  }

  private SctpPacket(byte[] rawData, int offset, int length) throws IllegalRawDataException {
    this.header = new SctpHeader(rawData, offset, length);

    int payloadLength = length - header.length();
    if (payloadLength < 0) {
      throw new IllegalRawDataException(
              "The value of length param seems to be wrong: "
                + payloadLength
            );
    }

    if (payloadLength != 0) { // payloadLength is positive.
      this.payload
        = PacketFactories.getFactory(Packet.class, SctpPort.class)
            .newInstance(rawData, offset + header.length(), payloadLength, header.getDstPort());
    }
    else {
      this.payload = null;
    }
  }

  private SctpPacket(Builder builder) {
    if (
         builder == null
      || builder.srcPort == null
      || builder.dstPort == null
    ) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ").append(builder)
        .append(" builder.srcPort: ").append(builder.srcPort)
        .append(" builder.dstPort: ").append(builder.dstPort);
      throw new NullPointerException(sb.toString());
    }

    this.payload = builder.payloadBuilder != null ? builder.payloadBuilder.build() : null;
    this.header = new SctpHeader(
                    builder,
                    payload != null ? payload.getRawData() : new byte[0]
                  );
  }

  @Override
  public SctpHeader getHeader() {
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
   * @author Jeff Myers (myersj@gmail.com)
   * @since pcap4j 1.6.6
   */
  public static final
  class Builder extends AbstractBuilder {

    private SctpPort srcPort;
    private SctpPort dstPort;
    private int verificationTag;
    private int checksum;
    private Packet.Builder payloadBuilder;

    /**
     *
     */
    public Builder() {}

    /**
     *
     * @param packet packet
     */
    public Builder(SctpPacket packet) {
      this.srcPort = packet.header.srcPort;
      this.dstPort = packet.header.dstPort;
      this.verificationTag = packet.header.verificationTag;
      this.checksum = packet.header.checksum;
      this.payloadBuilder = packet.payload != null ? packet.payload.getBuilder() : null;
    }

    /**
     *
     * @param srcPort srcPort
     * @return this Builder object for method chaining.
     */
    public Builder srcPort(SctpPort srcPort) {
      this.srcPort = srcPort;
      return this;
    }

    /**
     *
     * @param dstPort dstPort
     * @return this Builder object for method chaining.
     */
    public Builder dstPort(SctpPort dstPort) {
      this.dstPort = dstPort;
      return this;
    }

    /**
     *
     * @param verificationTag verification tag
     * @return this Builder object for method chaining.
     */
    public Builder verificationTag(int verificationTag) {
      this.verificationTag = verificationTag;
      return this;
    }

    /**
     *
     * @param checksum checksum
     * @return this Builder object for method chaining.
     */
    public Builder checksum(int checksum) {
      this.checksum = checksum;
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
    public SctpPacket build() {
      return new SctpPacket(this);
    }

  }

  /**
   * @author Jeff Myers (myersj@gmail.com)
   * @since pcap4j 1.6.6
   */
  public static final class SctpHeader extends AbstractHeader {

    /*
     *  0                              16                            31
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |           Src Port            |           Dst Port            |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                        Verification Tag                       |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                            Checksum                           |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */

    /**
     *
     */
    private static final long serialVersionUID = -8223170335586535940L;

    private static final int SRC_PORT_OFFSET
      = 0;
    private static final int SRC_PORT_SIZE
      = SHORT_SIZE_IN_BYTES;
    private static final int DST_PORT_OFFSET
      = SRC_PORT_OFFSET + SRC_PORT_SIZE;
    private static final int DST_PORT_SIZE
      = SHORT_SIZE_IN_BYTES;
    private static final int VERIFICATION_TAG_OFFSET
      = DST_PORT_OFFSET + DST_PORT_SIZE;
    private static final int VERIFICAION_TAG_SIZE
      = INT_SIZE_IN_BYTES;
    private static final int CHECKSUM_OFFSET
      = VERIFICATION_TAG_OFFSET + VERIFICAION_TAG_SIZE;
    private static final int CHECKSUM_SIZE
      = INT_SIZE_IN_BYTES;
    private static final int SCTP_HEADER_SIZE
      = CHECKSUM_OFFSET + CHECKSUM_SIZE;

    private final SctpPort srcPort;
    private final SctpPort dstPort;
    private final int verificationTag;
    private final int checksum;

    private SctpHeader(byte[] rawData, int offset, int length) throws IllegalRawDataException {
      if (length < SCTP_HEADER_SIZE) {
        StringBuilder sb = new StringBuilder(80);
        sb.append("The data is too short to build a SCTP header(")
          .append(SCTP_HEADER_SIZE)
          .append(" bytes). data: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
        throw new IllegalRawDataException(sb.toString());
      }

      this.srcPort
        = SctpPort.getInstance(ByteArrays.getShort(rawData, SRC_PORT_OFFSET + offset));
      this.dstPort
        = SctpPort.getInstance(ByteArrays.getShort(rawData, DST_PORT_OFFSET + offset));
      this.verificationTag = ByteArrays.getInt(rawData, VERIFICATION_TAG_OFFSET + offset);
      this.checksum = ByteArrays.getInt(rawData, CHECKSUM_OFFSET + offset);
    }

    private SctpHeader(Builder builder, byte[] payload) {
      this.srcPort = builder.srcPort;
      this.dstPort = builder.dstPort;
      this.verificationTag = builder.verificationTag;
      this.checksum = builder.checksum;
    }

    /**
     *
     * @return srcPort
     */
    public SctpPort getSrcPort() {
      return srcPort;
    }

    /**
     *
     * @return dstPort
     */
    public SctpPort getDstPort() {
      return dstPort;
    }

    /**
     *
     * @return verification tag
     */
    public int getVerificationTag() {
      return verificationTag;
    }

    /**
     *
     * @return checksum
     */
    public int getChecksum() {
      return checksum;
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(ByteArrays.toByteArray(srcPort.value()));
      rawFields.add(ByteArrays.toByteArray(dstPort.value()));
      rawFields.add(ByteArrays.toByteArray(verificationTag));
      rawFields.add(ByteArrays.toByteArray(checksum));
      return rawFields;
    }

    @Override
    public int length() {
      return SCTP_HEADER_SIZE;
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[SCTP Header (")
        .append(length())
        .append(" bytes)]")
        .append(ls);
      sb.append("  Source port: ")
        .append(getSrcPort())
        .append(ls);
      sb.append("  Destination port: ")
        .append(getDstPort())
        .append(ls);
      sb.append("  Verification tag: 0x")
        .append(ByteArrays.toHexString(verificationTag, ""))
        .append(ls);
      sb.append("  Checksum: 0x")
        .append(ByteArrays.toHexString(checksum, ""))
        .append(ls);

      return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
      if (obj == this) { return true; }
      if (!this.getClass().isInstance(obj)) { return false; }

      SctpHeader other = (SctpHeader)obj;
      return
           checksum == other.checksum
        && verificationTag == other.verificationTag
        && srcPort.equals(other.srcPort)
        && dstPort.equals(other.dstPort);
    }

    @Override
    protected int calcHashCode() {
      int result = 17;
      result = 31 * result + srcPort.hashCode();
      result = 31 * result + dstPort.hashCode();
      result = 31 * result + verificationTag;
      result = 31 * result + checksum;
      return result;
    }

  }

}
