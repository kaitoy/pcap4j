/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.util.ArrayList;
import java.util.List;
import org.pcap4j.packet.DnsResourceRecord.DnsRData;
import org.pcap4j.util.ByteArrays;

/**
 * DNS TXT RDATA
 *
 * <pre style="white-space: pre;">
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * /                   TXT-DATA                    /
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * where:
 *
 * TXT-DATA        One or more &lt;character-string&gt;s.
 * </pre>
 *
 * @see <a href="https://tools.ietf.org/html/rfc1035">RFC 1035</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.1
 */
public final class DnsRDataTxt implements DnsRData {

  /** */
  private static final long serialVersionUID = 469382715852386597L;

  private final List<String> texts;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new DnsRDataTxt object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static DnsRDataTxt newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new DnsRDataTxt(rawData, offset, length);
  }

  private DnsRDataTxt(byte[] rawData, int offset, int length) throws IllegalRawDataException {
    this.texts = new ArrayList<String>();
    int cursor = 0;
    while (cursor < length) {
      int txtLen = rawData[offset + cursor] & 0xFF;
      cursor++;
      if (txtLen > length - cursor) {
        StringBuilder sb = new StringBuilder(200);
        sb.append("The data is too short to build a txt in DnsRDataTxt. data: ")
            .append(ByteArrays.toHexString(rawData, " "))
            .append(", offset: ")
            .append(offset)
            .append(", length: ")
            .append(length)
            .append(", cursor: ")
            .append(cursor);
        throw new IllegalRawDataException(sb.toString());
      }
      this.texts.add(new String(rawData, offset + cursor, txtLen));
      cursor += txtLen;
    }
  }

  private DnsRDataTxt(Builder builder) {
    if (builder == null || builder.texts == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ").append(builder).append(" builder.texts: ").append(builder.texts);
      throw new NullPointerException(sb.toString());
    }

    for (String text : builder.texts) {
      if (text.getBytes().length > 255) {
        throw new IllegalArgumentException("Length of a text must be less than 256. text: " + text);
      }
    }

    this.texts = new ArrayList<String>(builder.texts);
  }

  /** @return texts */
  public List<String> getTexts() {
    return new ArrayList<String>(texts);
  }

  @Override
  public int length() {
    int len = 0;
    for (String text : texts) {
      len += text.getBytes().length + 1;
    }
    return len;
  }

  @Override
  public byte[] getRawData() {
    List<byte[]> rawTexts = new ArrayList<byte[]>();
    int len = 0;
    for (String text : texts) {
      byte[] rawText = text.getBytes();
      rawTexts.add(rawText);
      len += rawText.length + 1;
    }

    byte[] data = new byte[len];
    int cursor = 0;
    for (byte[] rawText : rawTexts) {
      data[cursor] = (byte) rawText.length;
      cursor++;
      System.arraycopy(rawText, 0, data, cursor, rawText.length);
      cursor += rawText.length;
    }

    return data;
  }

  /** @return a new Builder object populated with this object's fields. */
  public Builder getBuilder() {
    return new Builder(this);
  }

  @Override
  public String toString() {
    return convertToString("", null);
  }

  @Override
  public String toString(String indent) {
    return convertToString(indent, null);
  }

  @Override
  public String toString(String indent, byte[] headerRawData) {
    if (headerRawData == null) {
      throw new NullPointerException("headerRawData is null.");
    }
    return convertToString(indent, headerRawData);
  }

  private String convertToString(String indent, byte[] headerRawData) {
    StringBuilder sb = new StringBuilder();
    String ls = System.getProperty("line.separator");

    sb.append(indent).append("TXT RDATA:").append(ls);
    for (String text : texts) {
      sb.append(indent).append("  TEXT: ").append(text).append(ls);
    }

    return sb.toString();
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + texts.hashCode();
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null) {
      return false;
    }
    if (getClass() != obj.getClass()) {
      return false;
    }
    DnsRDataTxt other = (DnsRDataTxt) obj;
    if (!texts.equals(other.texts)) {
      return false;
    }
    return true;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.7.1
   */
  public static final class Builder {

    private List<String> texts;

    /** */
    public Builder() {}

    private Builder(DnsRDataTxt obj) {
      this.texts = obj.texts;
    }

    /**
     * @param texts texts
     * @return this Builder object for method chaining.
     */
    public Builder texts(List<String> texts) {
      this.texts = texts;
      return this;
    }

    /** @return a new DnsRDataTxt object. */
    public DnsRDataTxt build() {
      return new DnsRDataTxt(this);
    }
  }
}
