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
public final class IpV4RecordRouteOption extends IpV4RouteOption {

  /*
   *  +--------+--------+--------+---------//--------+
   *  |00000111| length | pointer|     route data    |
   *  +--------+--------+--------+---------//--------+
   *    Type=7
   */

  /**
   *
   */
  private static final long serialVersionUID = -3620689882998826146L;

  /**
   *
   * @param rawData
   * @return
   */
  public static IpV4RecordRouteOption newInstance(byte[] rawData) {
    return new IpV4RecordRouteOption(rawData);
  }

  private IpV4RecordRouteOption(byte[] rawData) {
    super(rawData);
  }

  private IpV4RecordRouteOption(Builder builder) {
    super(builder);
  }

  public IpV4OptionType getType() {
    return IpV4OptionType.RECORD_ROUTE;
  }

  /**
   *
   * @return
   */
  public Builder getBuilder() {
    return new Builder(this);
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.11
   */
  public static final class
  Builder extends IpV4RouteOption.Builder<IpV4RecordRouteOption> {

    /**
     *
     */
    public Builder() {}

    private Builder(IpV4RecordRouteOption option) {
      super(option);
    }

    /**
     *
     * @return
     */
    public IpV4RecordRouteOption build() {
      return new IpV4RecordRouteOption(this);
    }

  }

}
