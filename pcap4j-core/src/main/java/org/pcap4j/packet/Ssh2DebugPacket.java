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
public final class Ssh2DebugPacket extends AbstractPacket {

  /** */
  private static final long serialVersionUID = 2146867728898738559L;

  private final Ssh2DebugHeader header;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new Ssh2DebugPacket object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static Ssh2DebugPacket newPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new Ssh2DebugPacket(rawData, offset, length);
  }

  private Ssh2DebugPacket(byte[] rawData, int offset, int length) throws IllegalRawDataException {
    this.header = new Ssh2DebugHeader(rawData, offset, length);
  }

  private Ssh2DebugPacket(Builder builder) {
    if (builder == null
        || builder.alwaysDisplay == null
        || builder.message == null
        || builder.languageTag == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ")
          .append(builder)
          .append(" builder.alwaysDisplay: ")
          .append(builder.alwaysDisplay)
          .append(" builder.message: ")
          .append(builder.message)
          .append(" builder.languageTag: ")
          .append(builder.languageTag);
      throw new NullPointerException(sb.toString());
    }

    this.header = new Ssh2DebugHeader(builder);
  }

  @Override
  public Ssh2DebugHeader getHeader() {
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

    private Ssh2Boolean alwaysDisplay;
    private Ssh2String message;
    private Ssh2String languageTag;

    /** */
    public Builder() {}

    private Builder(Ssh2DebugPacket packet) {
      this.alwaysDisplay = packet.header.alwaysDisplay;
      this.message = packet.header.message;
      this.languageTag = packet.header.languageTag;
    }

    /**
     * @param alwaysDisplay alwaysDisplay
     * @return this Builder object for method chaining.
     */
    public Builder alwaysDisplay(Ssh2Boolean alwaysDisplay) {
      this.alwaysDisplay = alwaysDisplay;
      return this;
    }

    /**
     * @param message message
     * @return this Builder object for method chaining.
     */
    public Builder message(Ssh2String message) {
      this.message = message;
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
    public Ssh2DebugPacket build() {
      return new Ssh2DebugPacket(this);
    }
  }

  /**
   * @author Kaito Yamada
   * @version pcap4j 1.0.1
   */
  public static final class Ssh2DebugHeader extends AbstractHeader {

    /*
     * http://tools.ietf.org/html/rfc4253
     *
     * byte      SSH_MSG_DEBUG
     * boolean   always_display
     * string    message in ISO-10646 UTF-8 encoding [RFC3629]
     * string    language tag [RFC3066]
     */

    /** */
    private static final long serialVersionUID = 873479096967096846L;

    private final Ssh2MessageNumber messageNumber = Ssh2MessageNumber.SSH_MSG_DEBUG;
    private final Ssh2Boolean alwaysDisplay;
    private final Ssh2String message;
    private final Ssh2String languageTag;

    private Ssh2DebugHeader(byte[] rawData, int offset, int length) throws IllegalRawDataException {
      if (length < 10) {
        StringBuilder sb = new StringBuilder(80);
        sb.append("The data is too short to build an SSH2 Debug header. data: ")
            .append(new String(rawData))
            .append(", offset: ")
            .append(offset)
            .append(", length: ")
            .append(length);
        throw new IllegalRawDataException(sb.toString());
      }
      if (!Ssh2MessageNumber.getInstance(rawData[offset]).equals(Ssh2MessageNumber.SSH_MSG_DEBUG)) {
        StringBuilder sb = new StringBuilder(120);
        sb.append("The data is not an SSH2 Debug message. data: ")
            .append(new String(rawData))
            .append(", offset: ")
            .append(offset)
            .append(", length: ")
            .append(length);
        throw new IllegalRawDataException(sb.toString());
      }

      int currentOffset = 1 + offset;
      int remainingLength = length - 1;
      this.alwaysDisplay = new Ssh2Boolean(rawData, currentOffset);
      currentOffset += alwaysDisplay.length();
      remainingLength -= alwaysDisplay.length();
      this.message = new Ssh2String(rawData, currentOffset, remainingLength);
      currentOffset += message.length();
      remainingLength -= message.length();
      this.languageTag = new Ssh2String(rawData, currentOffset, remainingLength);
    }

    private Ssh2DebugHeader(Builder builder) {
      this.alwaysDisplay = builder.alwaysDisplay;
      this.message = builder.message;
      this.languageTag = builder.languageTag;
    }

    /** @return messageNumber */
    public Ssh2MessageNumber getMessageNumber() {
      return messageNumber;
    }

    /** @return alwaysDisplay */
    public Ssh2Boolean getAlwaysDisplay() {
      return alwaysDisplay;
    }

    /** @return message */
    public Ssh2String getMessage() {
      return message;
    }

    /** @return languageTag */
    public Ssh2String getLanguageTag() {
      return languageTag;
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(new byte[] {messageNumber.value()});
      rawFields.add(alwaysDisplay.getRawData());
      rawFields.add(message.getRawData());
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

      sb.append("[SSH2 Debug Header (").append(length()).append(" bytes)]").append(ls);
      sb.append("  Message Number: ").append(messageNumber).append(ls);
      sb.append("  always_display: ").append(alwaysDisplay).append(ls);
      sb.append("  message: ").append(message).append(ls);
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

      Ssh2DebugHeader other = (Ssh2DebugHeader) obj;
      return message.equals(other.message)
          && languageTag.equals(other.languageTag)
          && alwaysDisplay.equals(other.alwaysDisplay);
    }

    @Override
    protected int calcHashCode() {
      int result = 17;
      result = 31 * result + alwaysDisplay.hashCode();
      result = 31 * result + message.hashCode();
      result = 31 * result + languageTag.hashCode();
      return result;
    }
  }
}
