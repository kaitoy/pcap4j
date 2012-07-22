/*_##########################################################################
  _##
  _##  Copyright (C) 2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.10
 */
public final class IpV6ExtDestinationOptionsPacket extends IpV6ExtOptionsPacket {

  /**
   *
   */
  private static final long serialVersionUID = 4366835831332691570L;

  /**
   *
   * @param rawData
   * @return
   */
  public static IpV6ExtDestinationOptionsPacket newPacket(byte[] rawData) {
    return new IpV6ExtDestinationOptionsPacket(rawData);
  }

  protected IpV6ExtDestinationOptionsPacket(byte[] rawData) {
    super(rawData);
  }

  protected IpV6ExtDestinationOptionsPacket(Builder builder) {
    super(builder);
  }

  @Override
  public Builder getBuilder() {
    return new Builder(this);
  }

  @Override
  public String getExactOptionName() {
    return "Destination Options";
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.10
   */
  public static class Builder extends org.pcap4j.packet.IpV6ExtOptionsPacket.Builder {

    public Builder(IpV6ExtDestinationOptionsPacket packet) {
      super(packet);
    }

    @Override
    public IpV6ExtOptionsPacket build() {
      return new IpV6ExtDestinationOptionsPacket(this);
    }

  }
}
