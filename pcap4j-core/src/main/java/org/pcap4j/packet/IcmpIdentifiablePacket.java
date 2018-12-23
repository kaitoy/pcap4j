/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.*;

import java.util.ArrayList;
import java.util.List;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
abstract class IcmpIdentifiablePacket extends AbstractPacket {

  /** */
  private static final long serialVersionUID = -424401780940103043L;

  protected IcmpIdentifiablePacket() {}

  protected IcmpIdentifiablePacket(Builder builder) {
    if (builder == null) {
      throw new NullPointerException("builder: " + builder);
    }
  }

  @Override
  public abstract IcmpIdentifiableHeader getHeader();

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.11
   */
  abstract static class Builder extends AbstractBuilder {

    private short identifier;
    private short sequenceNumber;

    /** */
    public Builder() {}

    protected Builder(IcmpIdentifiablePacket packet) {
      this.identifier = packet.getHeader().identifier;
      this.sequenceNumber = packet.getHeader().sequenceNumber;
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
     * @param sequenceNumber sequenceNumber
     * @return this Builder object for method chaining.
     */
    public Builder sequenceNumber(short sequenceNumber) {
      this.sequenceNumber = sequenceNumber;
      return this;
    }
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.11
   */
  abstract static class IcmpIdentifiableHeader extends AbstractHeader {

    /*
     *  0                            15
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |         Identifier            |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |       Sequence Number         |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *
     */

    /** */
    private static final long serialVersionUID = 8141956422232700L;

    private static final int IDENTIFIER_OFFSET = 0;
    private static final int IDENTIFIER_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int SEQUENCE_NUMBER_OFFSET = IDENTIFIER_OFFSET + IDENTIFIER_SIZE;
    private static final int SEQUENCE_NUMBER_SIZE = SHORT_SIZE_IN_BYTES;
    protected static final int ICMP_IDENTIFIABLE_HEADER_SIZE =
        SEQUENCE_NUMBER_OFFSET + SEQUENCE_NUMBER_SIZE;

    private final short identifier;
    private final short sequenceNumber;

    protected IcmpIdentifiableHeader(byte[] rawData, int offset, int length)
        throws IllegalRawDataException {
      if (length < ICMP_IDENTIFIABLE_HEADER_SIZE) {
        StringBuilder sb = new StringBuilder(80);
        sb.append("The data is too short to build an ")
            .append(getHeaderName())
            .append("(")
            .append(ICMP_IDENTIFIABLE_HEADER_SIZE)
            .append(" bytes). data: ")
            .append(ByteArrays.toHexString(rawData, " "))
            .append(", offset: ")
            .append(offset)
            .append(", length: ")
            .append(length);
        throw new IllegalRawDataException(sb.toString());
      }

      this.identifier = ByteArrays.getShort(rawData, IDENTIFIER_OFFSET + offset);
      this.sequenceNumber = ByteArrays.getShort(rawData, SEQUENCE_NUMBER_OFFSET + offset);
    }

    protected IcmpIdentifiableHeader(Builder builder) {
      this.identifier = builder.identifier;
      this.sequenceNumber = builder.sequenceNumber;
    }

    /** @return identifier */
    public short getIdentifier() {
      return identifier;
    }

    /** @return identifier */
    public int getIdentifierAsInt() {
      return identifier & 0xFFFF;
    }

    /** @return sequenceNumber */
    public short getSequenceNumber() {
      return sequenceNumber;
    }

    /** @return sequenceNumber */
    public int getSequenceNumberAsInt() {
      return sequenceNumber & 0xFFFF;
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(ByteArrays.toByteArray(identifier));
      rawFields.add(ByteArrays.toByteArray(sequenceNumber));
      return rawFields;
    }

    @Override
    public int length() {
      return ICMP_IDENTIFIABLE_HEADER_SIZE;
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
      sb.append("  Identifier: ").append(getIdentifierAsInt()).append(ls);
      sb.append("  SequenceNumber: ").append(getSequenceNumberAsInt()).append(ls);

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

      IcmpIdentifiableHeader other = (IcmpIdentifiableHeader) obj;
      return identifier == other.identifier && sequenceNumber == other.sequenceNumber;
    }

    @Override
    protected int calcHashCode() {
      int result = 17;
      result = 31 * result + identifier;
      result = 31 * result + sequenceNumber;
      return result;
    }

    protected abstract String getHeaderName();
  }
}
