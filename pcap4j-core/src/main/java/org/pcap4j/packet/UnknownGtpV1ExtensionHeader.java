/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.util.Arrays;
import org.pcap4j.packet.GtpV1Packet.GtpV1ExtensionHeader;
import org.pcap4j.packet.namednumber.GtpV1ExtensionHeaderType;
import org.pcap4j.util.ByteArrays;

/**
 * @author Leo Ma
 * @since pcap4j 1.7.7
 */
public final class UnknownGtpV1ExtensionHeader implements GtpV1ExtensionHeader {

  /** */
  private static final long serialVersionUID = -5097068268518946569L;

  private final byte length;
  private final byte[] content;
  private final GtpV1ExtensionHeaderType nextExtensionHeaderType;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new UnknownGtpV1ExtensionHeader object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static UnknownGtpV1ExtensionHeader newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new UnknownGtpV1ExtensionHeader(rawData, offset, length);
  }

  private UnknownGtpV1ExtensionHeader(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    if (length < 4) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("rawData length must be more than 3. rawData: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }

    if ((length % 4) != 0) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("rawData length must be multiple of 4. rawData: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }

    this.length = (byte) ((ByteArrays.getByte(rawData, offset)) & 0xFF);
    if (length < this.length * 4) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("The raw data is too short to build this extension header(")
          .append(this.length * 4)
          .append("). data: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }

    this.content = ByteArrays.getSubArray(rawData, 1 + offset, this.length * 4 - 2);
    this.nextExtensionHeaderType =
        GtpV1ExtensionHeaderType.getInstance(rawData[offset + length - 1]);
  }

  private UnknownGtpV1ExtensionHeader(Builder builder) {
    if (builder == null || builder.content == null || builder.nextExtensionHeaderType == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ")
          .append(builder)
          .append(" builder.content: ")
          .append(builder.content)
          .append(" builder.nextExtensionHeaderType: ")
          .append(builder.nextExtensionHeaderType);
      throw new NullPointerException(sb.toString());
    }

    this.content = new byte[builder.content.length];
    System.arraycopy(builder.content, 0, this.content, 0, builder.content.length);
    this.nextExtensionHeaderType = builder.nextExtensionHeaderType;

    if (builder.correctLengthAtBuild) {
      this.length = (byte) (length() / 4);
    } else {
      this.length = builder.length;
    }
  }

  /** @return length */
  public byte getLength() {
    return length;
  }

  /** @return length */
  public int getLengthAsInt() {
    return 0xFF & length;
  }

  /** @return data */
  public byte[] getContent() {
    byte[] copy = new byte[content.length];
    System.arraycopy(content, 0, copy, 0, content.length);
    return copy;
  }

  @Override
  public byte[] getRawData() {
    byte[] rawData = new byte[length()];
    rawData[0] = length;
    System.arraycopy(content, 0, rawData, 1, content.length);
    rawData[length() - 1] = nextExtensionHeaderType.value();
    return rawData;
  }

  @Override
  public int length() {
    return content.length + 2;
  }

  @Override
  public GtpV1ExtensionHeaderType getNextExtensionHeaderType() {
    return nextExtensionHeaderType;
  }

  /** @return a new Builder object populated with this object's fields. */
  public Builder getBuilder() {
    return new Builder(this);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("[length: ")
        .append(length)
        .append(" bytes] [Data: 0x")
        .append(ByteArrays.toHexString(content, ""))
        .append("] [next extension header type: ")
        .append(nextExtensionHeaderType.name())
        .append("]");
    return sb.toString();
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }
    if (this.getClass() != obj.getClass()) {
      return false;
    }

    UnknownGtpV1ExtensionHeader other = (UnknownGtpV1ExtensionHeader) obj;
    return length == other.length
        && nextExtensionHeaderType.equals(other.nextExtensionHeaderType)
        && Arrays.equals(content, other.content);
  }

  @Override
  public int hashCode() {
    int result = 17;
    result = 31 * result + length;
    result = 31 * result + Arrays.hashCode(content);
    result = 31 * result + nextExtensionHeaderType.hashCode();
    return result;
  }

  public static final class Builder implements LengthBuilder<UnknownGtpV1ExtensionHeader> {

    private byte length;
    private byte[] content;
    private GtpV1ExtensionHeaderType nextExtensionHeaderType;
    private boolean correctLengthAtBuild;

    /** */
    public Builder() {}

    private Builder(UnknownGtpV1ExtensionHeader header) {
      this.length = header.length;
      this.content = header.content;
      this.nextExtensionHeaderType = header.nextExtensionHeaderType;
    }

    /**
     * @param length length
     * @return this Builder object for method chaining.
     */
    public Builder length(byte length) {
      this.length = length;
      return this;
    }

    /**
     * @param content content
     * @return this Builder object for method chaining.
     */
    public Builder data(byte[] content) {
      this.content = content;
      return this;
    }

    /**
     * @param type type
     * @return this Builder object for method chaining.
     */
    public Builder type(GtpV1ExtensionHeaderType type) {
      this.nextExtensionHeaderType = type;
      return this;
    }

    @Override
    public Builder correctLengthAtBuild(boolean correctLengthAtBuild) {
      this.correctLengthAtBuild = correctLengthAtBuild;
      return this;
    }

    @Override
    public UnknownGtpV1ExtensionHeader build() {
      return new UnknownGtpV1ExtensionHeader(this);
    }
  }
}
