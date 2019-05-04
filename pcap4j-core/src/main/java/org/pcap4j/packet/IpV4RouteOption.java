/*_##########################################################################
  _##
  _##  Copyright (C) 2012 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES;

import java.net.Inet4Address;
import java.util.ArrayList;
import java.util.List;
import org.pcap4j.packet.IpV4Packet.IpV4Option;
import org.pcap4j.packet.namednumber.IpV4OptionType;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
abstract class IpV4RouteOption implements IpV4Option {

  /** */
  private static final long serialVersionUID = -2747065348720047861L;

  private final byte length;
  private final byte pointer;
  private final List<Inet4Address> routeData;

  protected IpV4RouteOption(byte[] rawData, int offset, int length) throws IllegalRawDataException {
    if (length < 3) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("The raw data length must be more than 2. rawData: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }
    if (rawData[0 + offset] != getType().value()) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("The type must be: ")
          .append(getType().valueAsString())
          .append(" rawData: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }

    this.length = rawData[1 + offset];
    int lengthFieldAsInt = getLengthAsInt();
    if (length < lengthFieldAsInt) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("The raw data is too short to build this option(")
          .append(lengthFieldAsInt)
          .append("). data: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }
    if (lengthFieldAsInt < 3) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("The length field value must be equal or more than 3 but it is: ")
          .append(lengthFieldAsInt);
      throw new IllegalRawDataException(sb.toString());
    }
    if ((lengthFieldAsInt - 3) % INET4_ADDRESS_SIZE_IN_BYTES != 0) {
      throw new IllegalRawDataException("Invalid length for this option: " + lengthFieldAsInt);
    }

    this.pointer = rawData[2 + offset];

    this.routeData = new ArrayList<Inet4Address>();
    for (int i = 3; i < lengthFieldAsInt; i += INET4_ADDRESS_SIZE_IN_BYTES) {
      routeData.add(ByteArrays.getInet4Address(rawData, i + offset));
    }
  }

  protected IpV4RouteOption(Builder<? extends IpV4RouteOption> builder) {
    if (builder == null || builder.routeData == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ")
          .append(builder)
          .append(" builder.routeData: ")
          .append(builder.routeData);
      throw new NullPointerException(sb.toString());
    }

    this.pointer = builder.pointer;
    this.routeData = new ArrayList<Inet4Address>(builder.routeData);

    if (builder.correctLengthAtBuild) {
      this.length = (byte) length();
    } else {
      this.length = builder.length;
    }
  }

  @Override
  public abstract IpV4OptionType getType();

  /** @return length */
  public byte getLength() {
    return length;
  }

  /** @return length */
  public int getLengthAsInt() {
    return 0xFF & length;
  }

  /** @return pointer */
  public byte getPointer() {
    return pointer;
  }

  /** @return pointer */
  public int getPointerAsInt() {
    return 0xFF & pointer;
  }

  /** @return routeData */
  public List<Inet4Address> getRouteData() {
    return new ArrayList<Inet4Address>(routeData);
  }

  @Override
  public int length() {
    return routeData.size() * 4 + 3;
  }

  @Override
  public byte[] getRawData() {
    byte[] rawData = new byte[length()];
    rawData[0] = getType().value();
    rawData[1] = length;
    rawData[2] = pointer;

    int i = 3;
    for (Inet4Address addr : routeData) {
      System.arraycopy(addr.getAddress(), 0, rawData, i, INET4_ADDRESS_SIZE_IN_BYTES);
      i += INET4_ADDRESS_SIZE_IN_BYTES;
    }

    return rawData;
  }

  /** @return a new Builder object populated with this object's fields. */
  public abstract Builder<? extends IpV4RouteOption> getBuilder();

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("[option-type: ").append(getType());
    sb.append("] [option-length: ").append(getLengthAsInt());
    sb.append(" bytes] [pointer: ").append(getPointerAsInt());
    sb.append("] [route data:");
    for (Inet4Address addr : routeData) {
      sb.append(" ").append(addr);
    }
    sb.append("]");
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

    IpV4RouteOption other = (IpV4RouteOption) obj;
    return length == other.length && pointer == other.pointer && routeData.equals(other.routeData);
  }

  @Override
  public int hashCode() {
    int result = 17;
    result = 31 * result + length;
    result = 31 * result + pointer;
    result = 31 * result + routeData.hashCode();
    return result;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.11
   */
  public abstract static class Builder<T extends IpV4RouteOption> implements LengthBuilder<T> {

    private byte length;
    private byte pointer;
    private List<Inet4Address> routeData;
    private boolean correctLengthAtBuild;

    /** */
    public Builder() {}

    protected Builder(IpV4RouteOption option) {
      this.length = option.length;
      this.pointer = option.pointer;
      this.routeData = option.routeData;
    }

    /**
     * @param length length
     * @return this Builder object for method chaining.
     */
    public Builder<T> length(byte length) {
      this.length = length;
      return this;
    }

    /**
     * @param pointer pointer
     * @return this Builder object for method chaining.
     */
    public Builder<T> pointer(byte pointer) {
      this.pointer = pointer;
      return this;
    }

    /**
     * @param routeData routeData
     * @return this Builder object for method chaining.
     */
    public Builder<T> routeData(List<Inet4Address> routeData) {
      this.routeData = routeData;
      return this;
    }

    @Override
    public Builder<T> correctLengthAtBuild(boolean correctLengthAtBuild) {
      this.correctLengthAtBuild = correctLengthAtBuild;
      return this;
    }

    @Override
    public abstract T build();
  }
}
