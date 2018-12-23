/*_##########################################################################
  _##
  _##  Copyright (C) 2017  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.util;

import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

/**
 * A utility class for operating on packets.
 *
 * @author Kaito Yamada
 * @since pcap4j 1.7.2
 */
public final class Packets {

  private Packets() {
    throw new AssertionError();
  }

  /**
   * Checks if the given packet contains a TCP packet ({@link TcpPacket}).
   *
   * @param packet packet
   * @return true if the packet contains a TCP packet; false otherwise.
   */
  public static boolean containsTcpPacket(Packet packet) {
    return packet.contains(TcpPacket.class);
  }

  /**
   * Checks if the given packet contains a Udp packet ({@link UdpPacket}).
   *
   * @param packet packet
   * @return true if the packet contains a UDP packet; false otherwise.
   */
  public static boolean containsUdpPacket(Packet packet) {
    return packet.contains(UdpPacket.class);
  }

  /**
   * Checks if the given packet contains an IPv4 packet ({@link IpV4Packet}).
   *
   * @param packet packet
   * @return true if the packet contains an IPv4 packet; false otherwise.
   */
  public static boolean containsIpV4Packet(Packet packet) {
    return packet.contains(IpV4Packet.class);
  }

  /**
   * Checks if the given packet contains an IPv6 packet ({@link IpV6Packet}).
   *
   * @param packet packet
   * @return true if the packet contains an IPv6 packet; false otherwise.
   */
  public static boolean containsIpV6Packet(Packet packet) {
    return packet.contains(IpV6Packet.class);
  }

  /**
   * Checks if the given packet contains an IP packet ({@link IpPacket}).
   *
   * @param packet packet
   * @return true if the packet contains an IP packet; false otherwise.
   */
  public static boolean containsIpPacket(Packet packet) {
    return packet.contains(IpPacket.class);
  }

  /**
   * Checks if the given packet contains an Ethernet packet ({@link EthernetPacket}).
   *
   * @param packet packet
   * @return true if the packet contains an Ethernet packet; false otherwise.
   */
  public static boolean containsEthernetPacket(Packet packet) {
    return packet.contains(EthernetPacket.class);
  }
}
