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
public final class IpV4StrictSourceRouteOption extends IpV4RouteOption {

  /*
   *  +--------+--------+--------+---------//--------+
   *  |10001001| length | pointer|     route data    |
   *  +--------+--------+--------+---------//--------+
   *   Type=137
   */

  /** */
  private static final long serialVersionUID = 4439878660976426283L;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new IpV4StrictSourceRouteOption object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static IpV4StrictSourceRouteOption newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new IpV4StrictSourceRouteOption(rawData, offset, length);
  }

  private IpV4StrictSourceRouteOption(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    super(rawData, offset, length);
  }

  private IpV4StrictSourceRouteOption(Builder builder) {
    super(builder);
  }

  @Override
  public IpV4OptionType getType() {
    return IpV4OptionType.STRICT_SOURCE_ROUTING;
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
  public static final class Builder extends IpV4RouteOption.Builder<IpV4StrictSourceRouteOption> {

    /** */
    public Builder() {}

    private Builder(IpV4StrictSourceRouteOption option) {
      super(option);
    }

    /** @return a new IpV4StrictSourceRouteOption object. */
    @Override
    public IpV4StrictSourceRouteOption build() {
      return new IpV4StrictSourceRouteOption(this);
    }
  }
}
