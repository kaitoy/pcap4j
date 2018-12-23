/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import org.pcap4j.packet.namednumber.RadiotapPresentBitNumber;
import org.pcap4j.util.ByteArrays;

/**
 * The present field of Radiotap header. Vendor namespaces are not supported yet.
 *
 * @see <a href="http://www.radiotap.org/">Radiotap</a>
 * @author Kaito Yamada
 * @since pcap4j 1.6.5
 */
public final class RadiotapPresentBitmask implements Serializable {

  /** */
  private static final long serialVersionUID = -4525947413002802922L;

  private final String namespace;
  private final List<RadiotapPresentBitNumber> bitNumbers;
  private final boolean radiotapNamespaceNext;
  private final boolean vendorNamespaceNext;
  private final boolean anotherBitmapFollows;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @param bitNumOffset bitNumOffset
   * @return a new RadiotapPresentBitmask object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static RadiotapPresentBitmask newInstance(
      byte[] rawData, int offset, int length, int bitNumOffset) throws IllegalRawDataException {
    return newInstance(rawData, offset, length, bitNumOffset, "");
  }

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @param bitNumOffset bitNumOffset
   * @param namespace namespace
   * @return a new RadiotapPresentBitmask object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static RadiotapPresentBitmask newInstance(
      byte[] rawData, int offset, int length, int bitNumOffset, String namespace)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new RadiotapPresentBitmask(rawData, offset, length, bitNumOffset, namespace);
  }

  private RadiotapPresentBitmask(
      byte[] rawData, int offset, int length, int bitNumOffset, String namespace)
      throws IllegalRawDataException {
    if (ByteArrays.INT_SIZE_IN_BYTES > length) {
      StringBuilder sb = new StringBuilder(200);
      sb.append("The data is too short to build a RadiotapPresentBitmask (")
          .append(ByteArrays.INT_SIZE_IN_BYTES)
          .append(" bytes). data: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }

    this.namespace = namespace;
    this.bitNumbers = new ArrayList<RadiotapPresentBitNumber>();

    int bitNum = bitNumOffset;
    boolean isRadiotapNsBitSet = false;
    boolean isVendorNsBitSet = false;
    boolean isAnotherBitmapFollowsBitSet = false;
    for (int i = 0; i < 4; i++) {
      byte mask = rawData[offset + i];
      for (int j = 0; j < 8; j++) {
        if ((mask & 1) != 0) {
          switch (bitNum % 32) {
            case RadiotapPresentBitNumber.RADIOTAP_NAMESPACE:
              isRadiotapNsBitSet = true;
              break;
            case RadiotapPresentBitNumber.VENDOR_NAMESPACE:
              isVendorNsBitSet = true;
              break;
            case RadiotapPresentBitNumber.ANOTHER_BITMAP_FOLLOWS:
              isAnotherBitmapFollowsBitSet = true;
              break;
            default:
              bitNumbers.add(RadiotapPresentBitNumber.getInstance(bitNum, namespace));
          }
        }
        bitNum++;
        mask >>>= 1;
      }
    }
    this.radiotapNamespaceNext = isRadiotapNsBitSet;
    this.vendorNamespaceNext = isVendorNsBitSet;
    this.anotherBitmapFollows = isAnotherBitmapFollowsBitSet;
  }

  private RadiotapPresentBitmask(Builder builder) {
    if (builder == null || builder.namespace == null || builder.bitNumbers == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ")
          .append(builder)
          .append(" builder.namespace: ")
          .append(builder.namespace)
          .append(" builder.bitNumbers: ")
          .append(builder.bitNumbers);
      throw new NullPointerException(sb.toString());
    }
    if (builder.bitNumbers.size() > 29) {
      throw new IllegalArgumentException(
          "bitNumbers.size() must be less than 30 but is: " + builder.bitNumbers.size());
    }

    this.namespace = builder.namespace;
    this.bitNumbers = new ArrayList<RadiotapPresentBitNumber>(builder.bitNumbers);
    this.radiotapNamespaceNext = builder.radiotapNamespaceNext;
    this.vendorNamespaceNext = builder.vendorNamespaceNext;
    this.anotherBitmapFollows = builder.anotherBitmapFollows;
  }

  /** @return namespace */
  public String getNamespace() {
    return namespace;
  }

  /** @return bitNumbers */
  public ArrayList<RadiotapPresentBitNumber> getBitNumbers() {
    return new ArrayList<RadiotapPresentBitNumber>(bitNumbers);
  }

  /** @return radiotapNamespaceNext */
  public boolean isRadiotapNamespaceNext() {
    return radiotapNamespaceNext;
  }

  /** @return vendorNamespaceNext */
  public boolean isVendorNamespaceNext() {
    return vendorNamespaceNext;
  }

  /** @return anotherBitmapFollows */
  public boolean isAnotherBitmapFollows() {
    return anotherBitmapFollows;
  }

  /** @return the bitmask */
  public byte[] getBitmask() {
    return getRawData();
  }

  /** @return length of this data */
  public int length() {
    return ByteArrays.INT_SIZE_IN_BYTES;
  }

  /** @return the raw data */
  public byte[] getRawData() {
    byte[] data = new byte[length()];
    for (RadiotapPresentBitNumber num : bitNumbers) {
      int bit = num.value() % 32;
      data[bit / ByteArrays.BYTE_SIZE_IN_BITS] |= 1 << bit % ByteArrays.BYTE_SIZE_IN_BITS;
    }
    if (radiotapNamespaceNext) {
      data[3] |= 0x20;
    }
    if (vendorNamespaceNext) {
      data[3] |= 0x40;
    }
    if (radiotapNamespaceNext) {
      data[3] |= 0x80;
    }
    return data;
  }

  /** @return a new Builder object populated with this object's fields. */
  public Builder getBuilder() {
    return new Builder(this);
  }

  @Override
  public String toString() {
    return toString("");
  }

  /**
   * @param indent indent
   * @return String representation of this object.
   */
  public String toString(String indent) {
    StringBuilder sb = new StringBuilder();
    String ls = System.getProperty("line.separator");

    sb.append(indent)
        .append("Present Bitmask (")
        .append(ByteArrays.toHexString(getRawData(), " "))
        .append("):")
        .append(ls)
        .append(indent)
        .append("  Present Fields: ")
        .append(ls);
    for (RadiotapPresentBitNumber num : bitNumbers) {
      sb.append(indent).append("    ").append(num).append(ls);
    }
    sb.append(indent)
        .append("  Radiotap NS Next: ")
        .append(radiotapNamespaceNext)
        .append(ls)
        .append(indent)
        .append("  Vendor NS Next: ")
        .append(vendorNamespaceNext)
        .append(ls)
        .append(indent)
        .append("  Another Bitmap Follows: ")
        .append(anotherBitmapFollows)
        .append(ls);

    return sb.toString();
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + (anotherBitmapFollows ? 1231 : 1237);
    result = prime * result + namespace.hashCode();
    result = prime * result + bitNumbers.hashCode();
    result = prime * result + (radiotapNamespaceNext ? 1231 : 1237);
    result = prime * result + (vendorNamespaceNext ? 1231 : 1237);
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }
    if (!this.getClass().isInstance(obj)) {
      return false;
    }

    RadiotapPresentBitmask other = (RadiotapPresentBitmask) obj;
    return bitNumbers.equals(other.bitNumbers)
        && namespace.equals(other.namespace)
        && radiotapNamespaceNext == other.radiotapNamespaceNext
        && vendorNamespaceNext == other.vendorNamespaceNext
        && anotherBitmapFollows == other.anotherBitmapFollows;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.6.5
   */
  public static final class Builder {

    private String namespace;
    private List<RadiotapPresentBitNumber> bitNumbers;
    private boolean radiotapNamespaceNext;
    private boolean vendorNamespaceNext;
    private boolean anotherBitmapFollows;

    /** */
    public Builder() {}

    private Builder(RadiotapPresentBitmask rp) {
      this.namespace = rp.namespace;
      this.bitNumbers = rp.bitNumbers;
      this.radiotapNamespaceNext = rp.radiotapNamespaceNext;
      this.vendorNamespaceNext = rp.vendorNamespaceNext;
      this.anotherBitmapFollows = rp.anotherBitmapFollows;
    }

    /**
     * @param namespace namespace
     * @return this Builder object for method chaining.
     */
    public Builder namespace(String namespace) {
      this.namespace = namespace;
      return this;
    }

    /**
     * @param bitNumbers bitNumbers
     * @return this Builder object for method chaining.
     */
    public Builder bitNumbers(List<RadiotapPresentBitNumber> bitNumbers) {
      this.bitNumbers = bitNumbers;
      return this;
    }

    /**
     * @param radiotapNamespaceNext radiotapNamespaceNext
     * @return this Builder object for method chaining.
     */
    public Builder radiotapNamespaceNext(boolean radiotapNamespaceNext) {
      this.radiotapNamespaceNext = radiotapNamespaceNext;
      return this;
    }

    /**
     * @param vendorNamespaceNext vendorNamespaceNext
     * @return this Builder object for method chaining.
     */
    public Builder vendorNamespaceNext(boolean vendorNamespaceNext) {
      this.vendorNamespaceNext = vendorNamespaceNext;
      return this;
    }

    /**
     * @param anotherBitmapFollows anotherBitmapFollows
     * @return this Builder object for method chaining.
     */
    public Builder anotherBitmapFollows(boolean anotherBitmapFollows) {
      this.anotherBitmapFollows = anotherBitmapFollows;
      return this;
    }

    /** @return a new RadiotapPresentBitmask object. */
    public RadiotapPresentBitmask build() {
      return new RadiotapPresentBitmask(this);
    }
  }
}
