/*_##########################################################################
  _##
  _##  Copyright (C) 2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.*;

import java.util.ArrayList;
import java.util.List;
import org.pcap4j.packet.namednumber.Ssh2DisconnectionReasonCode;
import org.pcap4j.packet.namednumber.Ssh2MessageNumber;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.0.1
 */
public final class Ssh2DisconnectPacket extends AbstractPacket {

  /** */
  private static final long serialVersionUID = -1484749154591150073L;

  private final Ssh2DisconnectHeader header;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new Ssh2DisconnectPacket object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static Ssh2DisconnectPacket newPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new Ssh2DisconnectPacket(rawData, offset, length);
  }

  private Ssh2DisconnectPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    this.header = new Ssh2DisconnectHeader(rawData, offset, length);
  }

  private Ssh2DisconnectPacket(Builder builder) {
    if (builder == null
        || builder.reasonCode == null
        || builder.description == null
        || builder.languageTag == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ")
          .append(builder)
          .append(" builder.reasonCode: ")
          .append(builder.reasonCode)
          .append(" builder.description: ")
          .append(builder.description)
          .append(" builder.languageTag: ")
          .append(builder.languageTag);
      throw new NullPointerException(sb.toString());
    }

    this.header = new Ssh2DisconnectHeader(builder);
  }

  @Override
  public Ssh2DisconnectHeader getHeader() {
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

    private Ssh2DisconnectionReasonCode reasonCode;
    private Ssh2String description;
    private Ssh2String languageTag;

    /** */
    public Builder() {}

    private Builder(Ssh2DisconnectPacket packet) {
      this.reasonCode = packet.header.reasonCode;
      this.description = packet.header.description;
      this.languageTag = packet.header.languageTag;
    }

    /**
     * @param reasonCode reasonCode
     * @return this Builder object for method chaining.
     */
    public Builder reasonCode(Ssh2DisconnectionReasonCode reasonCode) {
      this.reasonCode = reasonCode;
      return this;
    }

    /**
     * @param description description
     * @return this Builder object for method chaining.
     */
    public Builder description(Ssh2String description) {
      this.description = description;
      return this;
    }

    /**
     * @param languageTag languageTag
     * @return this Builder object for method chaining.
     */
    public Builder languageTag(Ssh2String languageTag) {
      this.languageTag = languageTag;
      return this;
    }

    @Override
    public Ssh2DisconnectPacket build() {
      return new Ssh2DisconnectPacket(this);
    }
  }

  /**
   * @author Kaito Yamada
   * @version pcap4j 1.0.1
   */
  public static final class Ssh2DisconnectHeader extends AbstractHeader {

    /*
     * http://tools.ietf.org/html/rfc4253
     *
     * byte      SSH_MSG_DISCONNECT
     * uint32    reason code
     * string    description in ISO-10646 UTF-8 encoding [RFC3629]
     * string    language tag [RFC3066]
     */

    /** */
    private static final long serialVersionUID = 873479096967096846L;

    private final Ssh2MessageNumber messageNumber = Ssh2MessageNumber.SSH_MSG_DISCONNECT;
    private final Ssh2DisconnectionReasonCode reasonCode;
    private final Ssh2String description;
    private final Ssh2String languageTag;

    private Ssh2DisconnectHeader(byte[] rawData, int offset, int length)
        throws IllegalRawDataException {
      if (length < 13) {
        StringBuilder sb = new StringBuilder(80);
        sb.append("The data is too short to build an SSH2 Disconnect header. data: ")
            .append(new String(rawData))
            .append(", offset: ")
            .append(offset)
            .append(", length: ")
            .append(length);
        throw new IllegalRawDataException(sb.toString());
      }
      if (!Ssh2MessageNumber.getInstance(rawData[offset])
          .equals(Ssh2MessageNumber.SSH_MSG_DISCONNECT)) {
        StringBuilder sb = new StringBuilder(120);
        sb.append("The data is not an SSH2 Disconnect message. data: ")
            .append(new String(rawData))
            .append(", offset: ")
            .append(offset)
            .append(", length: ")
            .append(length);
        throw new IllegalRawDataException(sb.toString());
      }

      int currentOffset = 1 + offset;
      int remainingLength = length - 1;
      this.reasonCode =
          Ssh2DisconnectionReasonCode.getInstance(ByteArrays.getInt(rawData, currentOffset));
      currentOffset += INT_SIZE_IN_BYTES;
      remainingLength -= INT_SIZE_IN_BYTES;
      this.description = new Ssh2String(rawData, currentOffset, remainingLength);
      currentOffset += description.length();
      remainingLength -= description.length();
      this.languageTag = new Ssh2String(rawData, currentOffset, remainingLength);
    }

    private Ssh2DisconnectHeader(Builder builder) {
      this.reasonCode = builder.reasonCode;
      this.description = builder.description;
      this.languageTag = builder.languageTag;
    }

    /** @return messageNumber */
    public Ssh2MessageNumber getMessageNumber() {
      return messageNumber;
    }

    /** @return reasonCode */
    public Ssh2DisconnectionReasonCode getReasonCode() {
      return reasonCode;
    }

    /** @return description */
    public Ssh2String getDescription() {
      return description;
    }

    /** @return languageTag */
    public Ssh2String getLanguageTag() {
      return languageTag;
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(new byte[] {messageNumber.value()});
      rawFields.add(ByteArrays.toByteArray(reasonCode.value()));
      rawFields.add(description.getRawData());
      rawFields.add(languageTag.getRawData());
      return rawFields;
    }

    @Override
    protected int calcLength() {
      return getRawData().length;
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[SSH2 Disconnect Header (").append(length()).append(" bytes)]").append(ls);
      sb.append("  Message Number: ").append(messageNumber).append(ls);
      sb.append("  reason code: ").append(reasonCode).append(ls);
      sb.append("  description: ").append(description).append(ls);
      sb.append("  language tag: ").append(languageTag).append(ls);

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

      Ssh2DisconnectHeader other = (Ssh2DisconnectHeader) obj;
      return reasonCode.equals(other.reasonCode)
          && description.equals(other.description)
          && languageTag.equals(other.languageTag);
    }

    @Override
    protected int calcHashCode() {
      int result = 17;
      result = 31 * result + reasonCode.hashCode();
      result = 31 * result + description.hashCode();
      result = 31 * result + languageTag.hashCode();
      return result;
    }
  }
}
