/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import org.pcap4j.packet.IpV4Packet.IpV4Option;
import org.pcap4j.packet.namednumber.IpV4OptionType;
import org.pcap4j.packet.namednumber.IpV4SecurityOptionCompartments;
import org.pcap4j.packet.namednumber.IpV4SecurityOptionHandlingRestrictions;
import org.pcap4j.packet.namednumber.IpV4SecurityOptionSecurity;
import org.pcap4j.packet.namednumber.IpV4SecurityOptionTransmissionControlCode;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class IpV4Rfc791SecurityOption implements IpV4Option {

  /*
   *  +--------+--------+---//---+---//---+---//---+---//---+
   *  |10000010|00001011|SSS  SSS|CCC  CCC|HHH  HHH|  TCC   |
   *  +--------+--------+---//---+---//---+---//---+---//---+
   *  Type=130 Length=11
   *
   *  Security (S field):  16 bits
   *  Compartments (C field):  16 bits
   *  Handling Restrictions (H field):  16 bits
   *  Transmission Control Code (TCC field):  24 bits
   */

  /** */
  private static final long serialVersionUID = -7385398208873489520L;

  private final IpV4OptionType type = IpV4OptionType.SECURITY;
  private final byte length;
  private final IpV4SecurityOptionSecurity security;
  private final IpV4SecurityOptionCompartments compartments;
  private final IpV4SecurityOptionHandlingRestrictions handlingRestrictions;
  private final IpV4SecurityOptionTransmissionControlCode tcc;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new IpV4Rfc791SecurityOption object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static IpV4Rfc791SecurityOption newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new IpV4Rfc791SecurityOption(rawData, offset, length);
  }

  private IpV4Rfc791SecurityOption(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    if (length < 11) {
      StringBuilder sb = new StringBuilder(50);
      sb.append("The raw data length must be more than 10. rawData: ")
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
    if (rawData[1 + offset] != 11) {
      throw new IllegalRawDataException("Invalid value of length field: " + rawData[1 + offset]);
    }

    this.length = rawData[1 + offset];
    this.security =
        IpV4SecurityOptionSecurity.getInstance(ByteArrays.getShort(rawData, 2 + offset));
    this.compartments =
        IpV4SecurityOptionCompartments.getInstance(ByteArrays.getShort(rawData, 4 + offset));
    this.handlingRestrictions =
        IpV4SecurityOptionHandlingRestrictions.getInstance(
            ByteArrays.getShort(rawData, 6 + offset));
    this.tcc =
        IpV4SecurityOptionTransmissionControlCode.getInstance(
            ByteArrays.getInt(rawData, 7 + offset) & 0x00FFFFFF);
  }

  private IpV4Rfc791SecurityOption(Builder builder) {
    if (builder == null) {
      throw new NullPointerException("builder: " + builder);
    }

    this.security = builder.security;
    this.compartments = builder.compartments;
    this.handlingRestrictions = builder.handlingRestrictions;
    this.tcc = builder.tcc;

    if (builder.correctLengthAtBuild) {
      this.length = (byte) length();
    } else {
      this.length = builder.length;
    }
  }

  @Override
  public IpV4OptionType getType() {
    return type;
  }

  /** @return length */
  public byte getLength() {
    return length;
  }

  /** @return length */
  public int getLengthAsInt() {
    return 0xFF & length;
  }

  /** @return security */
  public IpV4SecurityOptionSecurity getSecurity() {
    return security;
  }

  /** @return compartments */
  public IpV4SecurityOptionCompartments getCompartments() {
    return compartments;
  }

  /** @return handlingRestrictions */
  public IpV4SecurityOptionHandlingRestrictions getHandlingRestrictions() {
    return handlingRestrictions;
  }

  /** @return tcc */
  public IpV4SecurityOptionTransmissionControlCode getTcc() {
    return tcc;
  }

  @Override
  public int length() {
    return 11;
  }

  @Override
  public byte[] getRawData() {
    byte[] rawData = new byte[length()];
    rawData[0] = getType().value();
    rawData[1] = length;
    rawData[2] = (byte) (security.value() >> 8);
    rawData[3] = (byte) (security.value().shortValue());
    rawData[4] = (byte) (compartments.value() >> 8);
    rawData[5] = (byte) (compartments.value().shortValue());
    rawData[6] = (byte) (handlingRestrictions.value() >> 8);
    rawData[7] = (byte) (handlingRestrictions.value().shortValue());
    rawData[8] = (byte) (tcc.value() >> 16);
    rawData[9] = (byte) (tcc.value() >> 8);
    rawData[10] = (byte) (tcc.value().shortValue());
    return rawData;
  }

  /** @return a new Builder object populated with this object's fields. */
  public Builder getBuilder() {
    return new Builder(this);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("[option-type: ").append(getType());
    sb.append("] [option-length: ").append(getLengthAsInt());
    sb.append(" byte] [security: ").append(security);
    sb.append("] [compartments: ").append(compartments);
    sb.append("] [handlingRestrictions: ").append(handlingRestrictions);
    sb.append("] [tcc: ").append(tcc);
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

    IpV4Rfc791SecurityOption other = (IpV4Rfc791SecurityOption) obj;
    return length == other.length
        && security.equals(other.security)
        && compartments.equals(other.compartments)
        && handlingRestrictions.equals(other.handlingRestrictions)
        && tcc.equals(other.tcc);
  }

  @Override
  public int hashCode() {
    int result = 17;
    result = 31 * result + length;
    result = 31 * result + security.hashCode();
    result = 31 * result + compartments.hashCode();
    result = 31 * result + handlingRestrictions.hashCode();
    result = 31 * result + tcc.hashCode();
    return result;
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.11
   */
  public static final class Builder implements LengthBuilder<IpV4Rfc791SecurityOption> {

    private byte length;
    private IpV4SecurityOptionSecurity security;
    private IpV4SecurityOptionCompartments compartments;
    private IpV4SecurityOptionHandlingRestrictions handlingRestrictions;
    private IpV4SecurityOptionTransmissionControlCode tcc;
    private boolean correctLengthAtBuild;

    /** */
    public Builder() {}

    private Builder(IpV4Rfc791SecurityOption option) {
      this.length = option.length;
      this.security = option.security;
      this.compartments = option.compartments;
      this.handlingRestrictions = option.handlingRestrictions;
      this.tcc = option.tcc;
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
     * @param security security
     * @return this Builder object for method chaining.
     */
    public Builder security(IpV4SecurityOptionSecurity security) {
      this.security = security;
      return this;
    }

    /**
     * @param compartments compartments
     * @return this Builder object for method chaining.
     */
    public Builder compartments(IpV4SecurityOptionCompartments compartments) {
      this.compartments = compartments;
      return this;
    }

    /**
     * @param handlingRestrictions handlingRestrictions
     * @return this Builder object for method chaining.
     */
    public Builder handlingRestrictions(
        IpV4SecurityOptionHandlingRestrictions handlingRestrictions) {
      this.handlingRestrictions = handlingRestrictions;
      return this;
    }

    /**
     * @param tcc tcc
     * @return this Builder object for method chaining.
     */
    public Builder tcc(IpV4SecurityOptionTransmissionControlCode tcc) {
      this.tcc = tcc;
      return this;
    }

    @Override
    public Builder correctLengthAtBuild(boolean correctLengthAtBuild) {
      this.correctLengthAtBuild = correctLengthAtBuild;
      return this;
    }

    /** @return a new IpV4Rfc791SecurityOption object. */
    @Override
    public IpV4Rfc791SecurityOption build() {
      return new IpV4Rfc791SecurityOption(this);
    }
  }
}
