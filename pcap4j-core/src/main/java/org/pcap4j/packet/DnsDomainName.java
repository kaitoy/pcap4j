/*_##########################################################################
  _##
  _##  Copyright (C) 2016-2017  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.*;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import org.pcap4j.util.ByteArrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * DNS domain name
 *
 * <pre style="white-space: pre;">
 * labels:
 *     1            len             1            len
 * +-------+-------+-//-+-------+-------+-------+-//-+-------+--//--+-------+
 * |  len  |       label        |  len  |       label        |      |len (0)|
 * +-------+-------+-//-+-------+-------+-------+-//-+-------+--//--+-------+
 *
 * pointer:
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * | 1  1|                OFFSET                   |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * </pre>
 *
 * @see <a href="https://tools.ietf.org/html/rfc1035">RFC 1035</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.1
 */
public final class DnsDomainName implements Serializable {

  /** */
  private static final long serialVersionUID = -9123494137779222577L;

  private static final Logger LOG = LoggerFactory.getLogger(DnsDomainName.class);

  /** The root domain (zero) */
  public static final DnsDomainName ROOT_DOMAIN;

  static {
    try {
      ROOT_DOMAIN = new DnsDomainName(new byte[] {0}, 0, 1);
    } catch (IllegalRawDataException e) {
      throw new AssertionError("Never get here.");
    }
  }

  private final List<String> labels;
  private final String name;
  private final Short pointer;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new DnsDomainName object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static DnsDomainName newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new DnsDomainName(rawData, offset, length);
  }

  private DnsDomainName(byte[] rawData, int offset, int length) throws IllegalRawDataException {
    this.labels = new ArrayList<String>();
    int cursor = 0;
    Short foundPointer = null;
    boolean terminated = false;
    while (cursor < length) {
      int len = rawData[offset + cursor] & 0xFF;
      int flag = len & 0xC0;
      if (flag == 0x00) {
        if (len == 0) {
          terminated = true;
          break;
        }

        cursor++;
        if (length - cursor < len) {
          StringBuilder sb = new StringBuilder(200);
          sb.append("The data is too short to build a DnsDomainName. data: ")
              .append(ByteArrays.toHexString(rawData, " "))
              .append(", offset: ")
              .append(offset)
              .append(", length: ")
              .append(length)
              .append(", cursor: ")
              .append(cursor);
          throw new IllegalRawDataException(sb.toString());
        }

        labels.add(new String(rawData, offset + cursor, len));
        cursor += len;
        continue;
      } else if (flag == 0xC0) {
        if (length - cursor < SHORT_SIZE_IN_BYTES) {
          StringBuilder sb = new StringBuilder(200);
          sb.append("The data is too short to build a DnsDomainName. data: ")
              .append(ByteArrays.toHexString(rawData, " "))
              .append(", offset: ")
              .append(offset)
              .append(", length: ")
              .append(length)
              .append(", cursor: ")
              .append(cursor);
          throw new IllegalRawDataException(sb.toString());
        }

        foundPointer = (short) (ByteArrays.getShort(rawData, offset + cursor) & 0x3FFF);
        terminated = true;
        break;
      } else {
        StringBuilder sb = new StringBuilder(200);
        sb.append("A label must start with 00 or 11. data: ")
            .append(ByteArrays.toHexString(rawData, " "))
            .append(", offset: ")
            .append(offset)
            .append(", length: ")
            .append(length);
        throw new IllegalRawDataException(sb.toString());
      }
    }
    this.pointer = foundPointer;

    if (!terminated) {
      StringBuilder sb = new StringBuilder(200);
      sb.append("No null termination nor pointer. data: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }

    this.name = joinLabels(labels);
  }

  private DnsDomainName(Builder builder) {
    if (builder == null || builder.labels == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder").append(builder).append(" builder.labels: ").append(builder.labels);
      throw new NullPointerException(sb.toString());
    }

    for (String label : builder.labels) {
      if (label.getBytes().length > 63) {
        throw new IllegalArgumentException(
            "Length of a label must be less than 64. label: " + label);
      }
    }

    if (builder.pointer != null && (builder.pointer & 0xC000) != 0) {
      throw new IllegalArgumentException(
          "(builder.pointer & 0xC000) must be zero. builder.pointer: " + builder.pointer);
    }
    this.labels = new ArrayList<String>(builder.labels);
    this.name = joinLabels(labels);
    this.pointer = builder.pointer;
  }

  private String joinLabels(List<String> lbls) {
    if (lbls.size() == 0) {
      return "";
    }

    StringBuilder sb = new StringBuilder();
    Iterator<String> iter = lbls.iterator();
    while (true) {
      sb.append(iter.next());
      if (iter.hasNext()) {
        sb.append(".");
      } else {
        break;
      }
    }
    return sb.toString();
  }

  /** @return labels */
  public List<String> getLabels() {
    return new ArrayList<String>(labels);
  }

  /** @return name, which is made by joining labels with "." */
  public String getName() {
    return name;
  }

  /** @return pointer (0 - 16383 (inclusive)). May be null. */
  public Short getPointer() {
    return pointer;
  }

  /** @return pointer (0 - 16383 (inclusive)). May be null. */
  public Integer getPointerAsInt() {
    if (pointer != null) {
      return (int) pointer;
    } else {
      return null;
    }
  }

  /**
   * @param headerRawData the raw data of the DNS header including this domain name.
   * @return decompressed name.
   * @throws IllegalRawDataException if an error occurred during decompression or circular reference
   *     is detected.
   */
  public String decompress(byte[] headerRawData) throws IllegalRawDataException {
    if (headerRawData == null) {
      throw new NullPointerException("headerRawData is null.");
    }
    return decompress(headerRawData, new ArrayList<Short>());
  }

  private String decompress(byte[] headerRawData, List<Short> pointers)
      throws IllegalRawDataException {
    if (pointer == null) {
      return name;
    } else {
      if (pointers.contains(pointer)) {
        StringBuilder sb = new StringBuilder(200);
        sb.append("Circular reference detected. data: ")
            .append(ByteArrays.toHexString(headerRawData, " "))
            .append(", offset: ")
            .append(pointer)
            .append(", name: ")
            .append(name);
        throw new IllegalRawDataException(sb.toString());
      }
      pointers.add(pointer);
      StringBuilder sb = new StringBuilder();
      sb.append(name)
          .append(".")
          .append(
              new DnsDomainName(headerRawData, pointer, headerRawData.length - pointer)
                  .decompress(headerRawData, pointers));
      return sb.toString();
    }
  }

  /** @return a new Builder object populated with this object's fields. */
  public Builder getBuilder() {
    return new Builder(this);
  }

  /** @return the raw data. */
  public byte[] getRawData() {
    byte[] data = new byte[length()];
    int cursor = 0;
    for (String label : labels) {
      byte[] labelBytes = label.getBytes();
      data[cursor] = (byte) labelBytes.length;
      cursor++;
      System.arraycopy(labelBytes, 0, data, cursor, labelBytes.length);
      cursor += labelBytes.length;
    }
    if (pointer != null) {
      byte[] offsetBytes = ByteArrays.toByteArray(pointer);
      offsetBytes[0] |= 0xC0;
      System.arraycopy(offsetBytes, 0, data, cursor, offsetBytes.length);
    }
    return data;
  }

  /** @return length */
  public int length() {
    int len = 0;
    for (String label : labels) {
      len += label.length() + 1;
    }
    if (pointer != null) {
      len += 2;
    } else {
      len++;
    }
    return len;
  }

  @Override
  public String toString() {
    if (labels.size() == 0 && pointer == null) {
      return "<ROOT>";
    }

    if (pointer == null) {
      return name;
    } else {
      StringBuilder sb = new StringBuilder();
      sb.append("[name: ").append(name).append(", pointer: ").append(pointer).append("]");
      return sb.toString();
    }
  }

  /**
   * Convert this object to string representation including all fields info and decompressed domain
   * name.
   *
   * @param headerRawData the raw data of the DNS header including this domain name.
   * @return string representation of this object.
   */
  public String toString(byte[] headerRawData) {
    if (labels.size() == 0 && pointer == null) {
      return "<ROOT>";
    }

    if (pointer == null) {
      return name;
    } else {
      String decompressedName;
      try {
        decompressedName = decompress(headerRawData);
      } catch (IllegalRawDataException e) {
        LOG.error("Error occurred during building complete name.", e);
        decompressedName = "Error occurred during building complete name";
      }
      StringBuilder sb = new StringBuilder();
      sb.append(decompressedName)
          .append(" (name: ")
          .append(name)
          .append(", pointer: ")
          .append(pointer)
          .append(")");
      return sb.toString();
    }
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + name.hashCode();
    result = prime * result + ((pointer == null) ? 0 : pointer.hashCode());
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
    DnsDomainName other = (DnsDomainName) obj;
    if (!name.equals(other.name)) {
      return false;
    }
    if (pointer == null) {
      if (other.pointer != null) {
        return false;
      }
    } else if (!pointer.equals(other.pointer)) {
      return false;
    }
    return true;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.7.1
   */
  public static final class Builder {

    private List<String> labels;
    private Short pointer = null;

    /** */
    public Builder() {}

    private Builder(DnsDomainName obj) {
      this.labels = obj.labels;
      this.pointer = obj.pointer;
    }

    /**
     * @param labels labels
     * @return this Builder object for method chaining.
     */
    public Builder labels(List<String> labels) {
      this.labels = labels;
      return this;
    }

    /**
     * @param labels labels
     * @return this Builder object for method chaining.
     */
    public Builder labels(String[] labels) {
      this.labels = Arrays.asList(labels);
      return this;
    }

    /**
     * @param pointer pointer
     * @return this Builder object for method chaining.
     */
    public Builder pointer(Short pointer) {
      this.pointer = pointer;
      return this;
    }

    /** @return a new DnsDomainName object. */
    public DnsDomainName build() {
      return new DnsDomainName(this);
    }
  }
}
