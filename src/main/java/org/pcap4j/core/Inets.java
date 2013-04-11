/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.core;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import org.pcap4j.core.NativeMappings.in6_addr;
import org.pcap4j.core.NativeMappings.in_addr;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
final class Inets {

  static final short AF_UNSPEC = 0;
  static final short AF_INET = 2;
  static final short AF_NETBIOS = 17;
  static final short AF_INET6 = 23;
  static final short AF_IRDA = 26;
  static final short AF_BTM = 32;

  private Inets() { throw new AssertionError(); }

  static Inet4Address ntoInetAddress(in_addr in) {
    if (in == null) {
      return null;
    }

    return ByteArrays.getInet4Address(
             ByteArrays.toByteArray(
               in.s_addr,
               NativeMappings.NATIVE_BYTE_ORDER
             ),
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
