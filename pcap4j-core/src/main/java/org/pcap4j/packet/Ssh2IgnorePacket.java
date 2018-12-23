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
public final class Ssh2IgnorePacket extends AbstractPacket {

  /** */
  private static final long serialVersionUID = 2975421692356921479L;

  private final Ssh2IgnoreHeader header;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new Ssh2IgnorePacket object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static Ssh2IgnorePacket newPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new Ssh2IgnorePacket(rawData, offset, length);
  }

  private Ssh2IgnorePacket(byte[] rawData, int offset, int length) throws IllegalRawDataException {
    this.header = new Ssh2IgnoreHeader(rawData, offset, length);
  }

  private Ssh2IgnorePacket(Builder builder) {
    if (builder == null || builder.data == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ").append(builder).append(" builder.data: ").append(builder.data);
      throw new NullPointerException(sb.toString());
    }

    this.header = new Ssh2IgnoreHeader(builder);
  }

  @Override
  public Ssh2IgnoreHeader getHeader() {
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

    private Ssh2String data;

    /** */
    public Builder() {}

    private Builder(Ssh2IgnorePacket packet) {
      this.data = packet.header.data;
    }

    /**
     * @param data data
     * @return this Builder object for method chaining.
     */
    public Builder data(Ssh2String data) {
      this.data = data;
      return this;
    }

    @Override
    public Ssh2IgnorePacket build() {
      return new Ssh2IgnorePacket(this);
    }
  }

  /**
   * @author Kaito Yamada
   * @version pcap4j 1.0.1
   */
  public static final class Ssh2IgnoreHeader extends AbstractHeader {

    /*
     * http://tools.ietf.org/html/rfc4253
     *
     * byte      SSH_MSG_IGNORE
     * string    data
     */

    /** */
    private static final long serialVersionUID = 5835008308161430239L;

    private final Ssh2MessageNumber messageNumber = Ssh2MessageNumber.SSH_MSG_IGNORE;
    private final Ssh2String data;

    private Ssh2IgnoreHeader(byte[] rawData, int offset, int length)
        throws IllegalRawDataException {
      if (length < 5) {
        StringBuilder sb = new StringBuilder(80);
        sb.append("The data is too short to build an SSH2 Ignore header. data: ")
            .append(new String(rawData))
            .append(", offset: ")
            .append(offset)
            .append(", length: ")
            .append(length);
        throw new IllegalRawDataException(sb.toString());
      }
      if (!Ssh2MessageNumber.getInstance(rawData[offset])
          .equals(Ssh2MessageNumber.SSH_MSG_IGNORE)) {
        StringBuilder sb = new StringBuilder(120);
        sb.append("The data is not an SSH2 Ignore message. data: ")
            .append(new String(rawData))
            .append(", offset: ")
            .append(offset)
            .append(", length: ")
            .append(length);
        throw new IllegalRawDataException(sb.toString());
      }

      this.data = new Ssh2String(rawData, 1 + offset, length - 1);
    }

    private Ssh2IgnoreHeader(Builder builder) {
      this.data = builder.data;
    }

    /** @return messageNumber */
    public Ssh2MessageNumber getMessageNumber() {
      return messageNumber;
    }

    /** @return data */
    public Ssh2String getData() {
      return data;
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(new byte[] {messageNumber.value()});
      rawFields.add(data.getRawData());
      return rawFields;
    }

    @Override
    protected int calcLength() {
      return data.length() + 1;
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[SSH2 Ignore Header (").append(length()).append(" bytes)]").append(ls);
      sb.append("  Message Number: ").append(messageNumber).append(ls);
      sb.append("  data: ").append(data).append(ls);

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

      Ssh2IgnoreHeader other = (Ssh2IgnoreHeader) obj;
      return data.equals(other.data);
    }

    @Override
    protected int calcHashCode() {
      int result = 17;
      result = 31 * result + data.hashCode();
      return result;
    }
  }
}
