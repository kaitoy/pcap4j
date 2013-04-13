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
public final class IpV4LooseSourceRouteOption extends IpV4RouteOption {

  /*
   *  +--------+--------+--------+---------//--------+
   *  |10000011| length | pointer|     route data    |
   *  +--------+--------+--------+---------//--------+
   *   Type=131
   */

  /**
   *
   */
  private static final long serialVersionUID = 6450781975561609234L;

  /**
   *
   * @param rawData
   * @return a new IpV4LooseSourceRouteOption object.
   */
  public static IpV4LooseSourceRouteOption newInstance(byte[] rawData) {
    return new IpV4LooseSourceRouteOption(rawData);
  }

  private IpV4LooseSourceRouteOption(byte[] rawData) {
    super(rawData);
  }

  private IpV4LooseSourceRouteOption(Builder builder) {
    super(builder);
  }

  public IpV4OptionType getType() {
    return IpV4OptionType.LOOSE_SOURCE_ROUTING;
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
  Builder extends IpV4RouteOption.Builder<IpV4LooseSourceRouteOption> {

    /**
     *
     */
    public Builder() {}

    private Builder(IpV4LooseSourceRouteOption option) {
      super(option);
    }

    /**
     *
     * @return a new IpV4LooseSourceRouteOption object.
     */
    public IpV4LooseSourceRouteOption build() {
      return new IpV4LooseSourceRouteOption(this);
    }

  }

}
