/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.net.InetAddress;

import org.pcap4j.packet.namednumber.IpVersion;

/**
 * The interface representing an IP packet.
 *
 * @author Kaito Yamada
 * @since pcap4j 1.6.7
 */
public interface IpPacket extends Packet {

  @Override
  public IpHeader getHeader();

  /**
   * The interface representing an IP packet's header.
   *
   * @author Kaito Yamada
   * @since pcap4j 1.6.7
   */
  public interface IpHeader extends Header {

    /**
     * @return version
     */
    public IpVersion getVersion();

    /**
     * @return srcAddr
     */
    public InetAddress getSrcAddr();

    /**
     * @return dstAddr
     */
    public InetAddress getDstAddr();

  }

}
