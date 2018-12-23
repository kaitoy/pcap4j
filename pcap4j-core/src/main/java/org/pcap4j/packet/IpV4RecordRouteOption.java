/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import org.pcap4j.packet.namednumber.IpV4OptionType;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class IpV4RecordRouteOption extends IpV4RouteOption {

  /*
   *  +--------+--------+--------+---------//--------+
   *  |00000111| length | pointer|     route data    |
   *  +--------+--------+--------+---------//--------+
   *    Type=7
   */

  /** */
  private static final long serialVersionUID = -3620689882998826146L;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new IpV4RecordRouteOption object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static IpV4RecordRouteOption newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new IpV4RecordRouteOption(rawData, offset, length);
  }

  private IpV4RecordRouteOption(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    super(rawData, offset, length);
  }

  private IpV4RecordRouteOption(Builder builder) {
    super(builder);
  }

  @Override
  public IpV4OptionType getType() {
    return IpV4OptionType.RECORD_ROUTE;
  }

  /** @return a new Builder object populated with this object's fields. */
  @Override
  public Builder getBuilder() {
    return new Builder(this);
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.11
   */
  public static final class Builder extends IpV4RouteOption.Builder<IpV4RecordRouteOption> {

    /** */
    public Builder() {}

    private Builder(IpV4RecordRouteOption option) {
      super(option);
    }

    /** @return a new IpV4RecordRouteOption object. */
    @Override
    public IpV4RecordRouteOption build() {
      return new IpV4RecordRouteOption(this);
    }
  }
}
