/*_##########################################################################
  _##
  _##  Copyright (C) 2012 Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import org.pcap4j.packet.namednumber.IpV4OptionType;

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

  /**
   *
   */
  private static final long serialVersionUID = 4439878660976426283L;

  /**
   *
   * @param rawData
   * @return a new IpV4StrictSourceRouteOption object.
   */
  public static IpV4StrictSourceRouteOption newInstance(byte[] rawData) {
    return new IpV4StrictSourceRouteOption(rawData);
  }

  private IpV4StrictSourceRouteOption(byte[] rawData) {
    super(rawData);
  }

  private IpV4StrictSourceRouteOption(Builder builder) {
    super(builder);
  }

  public IpV4OptionType getType() {
    return IpV4OptionType.STRICT_SOURCE_ROUTING;
  }

  /**
   *
   * @return a new Builder object populated with this object's fields.
   */
  public Builder getBuilder() {
    return new Builder(this);
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.11
   */
  public static final class
  Builder extends IpV4RouteOption.Builder<IpV4StrictSourceRouteOption> {

    /**
     *
     */
    public Builder() {}

    private Builder(IpV4StrictSourceRouteOption option) {
      super(option);
    }

    /**
     *
     * @return a new IpV4StrictSourceRouteOption object.
     */
    public IpV4StrictSourceRouteOption build() {
      return new IpV4StrictSourceRouteOption(this);
    }

  }

}
