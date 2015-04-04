/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2012  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.core;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import org.pcap4j.Pcap4jPropertiesLoader;
import org.pcap4j.core.NativeMappings.in6_addr;
import org.pcap4j.core.NativeMappings.in_addr;
import org.pcap4j.util.ByteArrays;
import com.sun.jna.Platform;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
final class Inets {

  static final short AF_UNSPEC = 0;
  static final short AF_INET;
  static final short AF_INET6;
  static final short AF_PACKET;
  static final short AF_LINK;

  static {
    Integer afInet = Pcap4jPropertiesLoader.getInstance().getAfInet();
    if (afInet != null) {
      AF_INET = (short)afInet.intValue();
    }
    else {
      AF_INET = 2;
    }

    Integer afInet6 = Pcap4jPropertiesLoader.getInstance().getAfInet6();
    if (afInet6 != null) {
      AF_INET6 = (short)afInet6.intValue();
    }
    else {
      if (Platform.isMac()) {
        AF_INET6 = 30;
      }
      else if (Platform.isFreeBSD()) {
        AF_INET6 = 28;
      }
      else if (Platform.isLinux()) {
        AF_INET6 = 10;
      }
      else {
        AF_INET6 = 23;
      }
    }

    Integer afPacket = Pcap4jPropertiesLoader.getInstance().getAfPacket();
    if (afPacket != null) {
      AF_PACKET = (short)afPacket.intValue();
    }
    else {
      AF_PACKET = 17;
    }

    Integer afLink = Pcap4jPropertiesLoader.getInstance().getAfLink();
    if (afLink != null) {
      AF_LINK = (short)afLink.intValue();
    }
    else {
      AF_LINK = 18;
    }
  }

  private Inets() { throw new AssertionError(); }

  static Inet4Address ntoInetAddress(in_addr in) {
    if (in == null) {
      return null;
    }
    return itoInetAddress(in.s_addr);
  }

  static Inet4Address itoInetAddress(int i) {
    return ByteArrays.getInet4Address(
             ByteArrays.toByteArray(i, NativeMappings.NATIVE_BYTE_ORDER),
             0
           );
  }

  static Inet6Address ntoInetAddress(in6_addr in6) {
    if (in6 == null) {
      return null;
    }

    try {
      return (Inet6Address)InetAddress.getByAddress(in6.s6_addr);
    } catch (UnknownHostException e) {
      throw new AssertionError();
    }
  }

}
