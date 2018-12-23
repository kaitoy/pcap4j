/*_##########################################################################
  _##
  _##  Copyright (C) 2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.util.ArrayList;
import java.util.List;
import org.pcap4j.packet.namednumber.Ssh2MessageNumber;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.0.1
 */
public final class Ssh2UnimplementedPacket extends AbstractPacket {

  /** */
  private static final long serialVersionUID = -8439655903366307992L;

  private final Ssh2UnimplementedHeader header;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new Ssh2UnimplementedPacket object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static Ssh2UnimplementedPacket newPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new Ssh2UnimplementedPacket(rawData, offset, length);
  }

  private Ssh2UnimplementedPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    this.header = new Ssh2UnimplementedHeader(rawData, offset, length);
  }

  private Ssh2UnimplementedPacket(Builder builder) {
    if (builder == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ").append(builder);
      throw new NullPointerException(sb.toString());
    }

    this.header = new Ssh2UnimplementedHeader(builder);
  }

  @Override
  public Ssh2UnimplementedHeader getHeader() {
    return header;
  }

  @Override
  public Builder getBuilder() {
    return new Builder(this);
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.0.1
   */
  public static final class Builder extends AbstractBuilder {

    private int sequenceNumber;

    /** */
    public Builder() {}

    private Builder(Ssh2UnimplementedPacket packet) {
      this.sequenceNumber = packet.header.sequenceNumber;
    }

    /**
     * @param sequenceNumber sequenceNumber
     * @return this Builder object for method chaining.
     */
    public Builder sequenceNumber(int sequenceNumber) {
      this.sequenceNumber = sequenceNumber;
      return this;
    }

    @Override
    public Ssh2UnimplementedPacket build() {
      return new Ssh2UnimplementedPacket(this);
    }
  }

  /**
   * @author Kaito Yamada
   * @version pcap4j 1.0.1
   */
  public static final class Ssh2UnimplementedHeader extends AbstractHeader {

    /*
     * http://tools.ietf.org/html/rfc4253
     *
     * byte      SSH_MSG_UNIMPLEMENTED
     * uint32    packet sequence number of rejected message
     */

    /** */
    private static final long serialVersionUID = 1942311282988657234L;

    private final Ssh2MessageNumber messageNumber = Ssh2MessageNumber.SSH_MSG_UNIMPLEMENTED;
    private final int sequenceNumber;

    private Ssh2UnimplementedHeader(byte[] rawData, int offset, int length)
        throws IllegalRawDataException {
      if (length < 5) {
        StringBuilder sb = new StringBuilder(80);
        sb.append("The data is too short to build an SSH2 Unimplemented header. data: ")
            .append(new String(rawData))
            .append(", offset: ")
            .append(offset)
            .append(", length: ")
            .append(length);
        throw new IllegalRawDataException(sb.toString());
      }
      if (!Ssh2MessageNumber.getInstance(rawData[offset])
          .equals(Ssh2MessageNumber.SSH_MSG_UNIMPLEMENTED)) {
        StringBuilder sb = new StringBuilder(120);
        sb.append("The data is not an SSH2 Unimplemented message. data: ")
            .append(new String(rawData))
            .append(", offset: ")
            .append(offset)
            .append(", length: ")
            .append(length);
        throw new IllegalRawDataException(sb.toString());
      }

      this.sequenceNumber = ByteArrays.getInt(rawData, 1 + offset);
    }

    private Ssh2UnimplementedHeader(Builder builder) {
      this.sequenceNumber = builder.sequenceNumber;
    }

    /** @return messageNumber */
    public Ssh2MessageNumber getMessageNumber() {
      return messageNumber;
    }

    /** @return sequenceNumber */
    public int getSequenceNumber() {
      return sequenceNumber;
    }

    /** @return sequenceNumber */
    public long getSequenceNumberAsLong() {
      return sequenceNumber & 0xFFFFFFFFL;
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(new byte[] {messageNumber.value()});
      rawFields.add(ByteArrays.toByteArray(sequenceNumber));
      return rawFields;
    }

    @Override
    public int length() {
      return 5;
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[SSH2 Unimplemented Header (").append(length()).append(" bytes)]").append(ls);
      sb.append("  Message Number: ").append(messageNumber).append(ls);
      sb.append("  packet sequence number: ").append(getSequenceNumberAsLong()).append(ls);

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

      Ssh2UnimplementedHeader other = (Ssh2UnimplementedHeader) obj;
      return sequenceNumber == other.sequenceNumber;
    }

    @Override
    protected int calcHashCode() {
      int result = 17;
      result = 31 * result + sequenceNumber;
      return result;
    }
  }
}
