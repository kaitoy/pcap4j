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
public final class IpV4LooseSourceRouteOption extends IpV4RouteOption {

  /*
   *  +--------+--------+--------+---------//--------+
   *  |10000011| length | pointer|     route data    |
   *  +--------+--------+--------+---------//--------+
   *   Type=131
   */

  /** */
  private static final long serialVersionUID = 6450781975561609234L;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new IpV4LooseSourceRouteOption object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static IpV4LooseSourceRouteOption newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new IpV4LooseSourceRouteOption(rawData, offset, length);
  }

  private IpV4LooseSourceRouteOption(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    super(rawData, offset, length);
  }

  private IpV4LooseSourceRouteOption(Builder builder) {
    super(builder);
  }

  @Override
  public IpV4OptionType getType() {
    return IpV4OptionType.LOOSE_SOURCE_ROUTING;
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
  public static final class Builder extends IpV4RouteOption.Builder<IpV4LooseSourceRouteOption> {

    /** */
    public Builder() {}

    private Builder(IpV4LooseSourceRouteOption option) {
      super(option);
    }

    /** @return a new IpV4LooseSourceRouteOption object. */
    @Override
    public IpV4LooseSourceRouteOption build() {
      return new IpV4LooseSourceRouteOption(this);
    }
  }
}
