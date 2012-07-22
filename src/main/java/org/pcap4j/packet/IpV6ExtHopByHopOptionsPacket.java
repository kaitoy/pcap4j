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
public final class IpV6ExtHopByHopOptionsPacket extends IpV6ExtOptionsPacket {

  /**
   *
   */
  private static final long serialVersionUID = -2955255397586708988L;

  /**
   *
   * @param rawData
   * @return
   */
  public static IpV6ExtHopByHopOptionsPacket newPacket(byte[] rawData) {
    return new IpV6ExtHopByHopOptionsPacket(rawData);
  }

  protected IpV6ExtHopByHopOptionsPacket(byte[] rawData) {
    super(rawData);
  }

  protected IpV6ExtHopByHopOptionsPacket(Builder builder) {
    super(builder);
  }

  @Override
  public Builder getBuilder() {
    return new Builder(this);
  }

  @Override
  public String getExactOptionName() {
    return "Hop-by-Hop Options";
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.10
   */
  public static class Builder extends org.pcap4j.packet.IpV6ExtOptionsPacket.Builder {

    public Builder(IpV6ExtHopByHopOptionsPacket packet) {
      super(packet);
    }

    @Override
    public IpV6ExtOptionsPacket build() {
      return new IpV6ExtHopByHopOptionsPacket(this);
    }

  }
}
