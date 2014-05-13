/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Kaito Yamada
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
   * @return a new IpV4RecordRouteOption object.
   * @throws IllegalRawDataException
   * @throws NullPointerException if the rawData argument is null.
   * @throws IllegalArgumentException if the rawData argument is empty.
   */
  public static IpV4RecordRouteOption newInstance(
    byte[] rawData
  ) throws IllegalRawDataException {
    if (rawData == null) {
      throw new NullPointerException("rawData must not be null.");
    }
    if (rawData.length == 0) {
      throw new IllegalArgumentException("rawData is empty.");
    }
    return new IpV4RecordRouteOption(rawData);
  }

  private IpV4RecordRouteOption(byte[] rawData) throws IllegalRawDataException {
    super(rawData);
  }

  private IpV4RecordRouteOption(Builder builder) {
    super(builder);
  }

  @Override
  public IpV4OptionType getType() {
    return IpV4OptionType.RECORD_ROUTE;
  }

  /**
   *
   * @return a new Builder object populated with this object's fields.
   */
  @Override
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
     * @return a new IpV4RecordRouteOption object.
     */
    @Override
    public IpV4RecordRouteOption build() {
      return new IpV4RecordRouteOption(this);
    }

  }

}
