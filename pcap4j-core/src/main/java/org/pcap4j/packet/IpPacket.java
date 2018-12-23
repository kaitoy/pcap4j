/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.net.InetAddress;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;

/**
 * The interface representing an IP packet.
 *
 * @author Kaito Yamada
 * @since pcap4j 1.7.0
 */
public interface IpPacket extends Packet {

  @Override
  public IpHeader getHeader();

  /**
   * The interface representing an IP packet's header.
   *
   * @author Kaito Yamada
   * @since pcap4j 1.7.0
   */
  public interface IpHeader extends Header {

    /** @return version */
    public IpVersion getVersion();

    /** @return an IpNumber object which indicates the protocol of the following header. */
    public IpNumber getProtocol();

    /** @return srcAddr */
    public InetAddress getSrcAddr();

    /** @return dstAddr */
    public InetAddress getDstAddr();
  }
}
