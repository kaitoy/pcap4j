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

import java.util.HashSet;
import java.util.Set;

/**
 * A utility class for operating on packets.
 * @author Kaito Yamada
 * @since pcap4j 1.7.2
 */
public final class Packets {

  private Packets() { throw new AssertionError(); }

  /**
   * Checks if the given packet contains a TCP packet ({@link TcpPacket}).
   * @param packet packet
   * @return true if the packet contains a TCP packet; false otherwise.
   * @throws NullPointerException if null is given.
   */
  public static boolean containsTcpPacket(Packet packet) {
    return packet.contains(TcpPacket.class);
  }

  /**
   * Checks if the given packet contains a Udp packet ({@link UdpPacket}).
   * @param packet packet
   * @return true if the packet contains a UDP packet; false otherwise.
   * @throws NullPointerException if null is given.
   */
  public static boolean containsUdpPacket(Packet packet) {
    return packet.contains(UdpPacket.class);
  }

  /**
   * Checks if the given packet contains an IPv4 packet ({@link IpV4Packet}).
   * @param packet packet
   * @return true if the packet contains an IPv4 packet; false otherwise.
   * @throws NullPointerException if null is given.
   */
  public static boolean containsIpV4Packet(Packet packet) {
    return packet.contains(IpV4Packet.class);
  }

  /**
   * Checks if the given packet contains an IPv6 packet ({@link IpV6Packet}).
   * @param packet packet
   * @return true if the packet contains an IPv6 packet; false otherwise.
   * @throws NullPointerException if null is given.
   */
  public static boolean containsIpV6Packet(Packet packet) {
    return packet.contains(IpV6Packet.class);
  }

  /**
   * Checks if the given packet contains an IP packet ({@link IpPacket}).
   * @param packet packet
   * @return true if the packet contains an IP packet; false otherwise.
   * @throws NullPointerException if null is given.
   */
  public static boolean containsIpPacket(Packet packet) {
    return packet.contains(IpPacket.class);
  }

  /**
   * Checks if the given packet contains an Ethernet packet ({@link EthernetPacket}).
   * @param packet packet
   * @return true if the packet contains an Ethernet packet; false otherwise.
   * @throws NullPointerException if null is given.
   */
  public static boolean containsEthernetPacket(Packet packet) {
    return packet.contains(EthernetPacket.class);
  }

  /**
   *
   * @param packet packet
   * @return a TCP session key
   * @throws IllegalArgumentException if the given packet doesn't contain IP and TCP packet.
   */
  public static Set<SocketAddress> createTcpSessionKey(Packet packet) {
    IpPacket ip = packet.get(IpPacket.class);
    if (ip == null) {
      throw new IllegalArgumentException("Failed to get an IP packet. packet: " + packet);
    }
    TcpPacket tcp = packet.get(TcpPacket.class);
    if (tcp == null) {
      throw new IllegalArgumentException("Failed to get a TCP packet. packet: " + packet);
    }

    Set<SocketAddress> key = new HashSet<>();
    key.add(new SocketAddress(ip.getHeader().getSrcAddr(), tcp.getHeader().getSrcPort().value()));
    key.add(new SocketAddress(ip.getHeader().getDstAddr(), tcp.getHeader().getDstPort().value()));
    return key;
  }

}
