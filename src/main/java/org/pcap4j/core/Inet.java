/*_##########################################################################
  _##
  _##  Copyright (C) 2011  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.core;

import java.net.InetAddress;
import java.net.UnknownHostException;
import org.pcap4j.core.NativeMappings.in6_addr;
import org.pcap4j.core.NativeMappings.in_addr;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
final class Inet {

  /**
   *
   */
  public static final short AF_UNSPEC = 0;

  /**
   *
   */
  public static final short AF_INET = 2;

  /**
   *
   */
  public static final short AF_NETBIOS = 17;

  /**
   *
   */
  public static final short AF_INET6 = 23;

  /**
   *
   */
  public static final short AF_IRDA = 26;

  /**
   *
   */
  public static final short AF_BTM = 32;

  private Inet() { throw new AssertionError(); }

  /**
   *
   * @param in
   * @return
   */
  public static InetAddress ntoInetAddress(in_addr in) {
    if (in == null) {
      return null;
    }

    byte[] rawAddr
      = new byte[] {
          (byte)(in.s_addr       & 0xFF),
          (byte)(in.s_addr >>  8 & 0xFF),
          (byte)(in.s_addr >> 16 & 0xFF),
          (byte)(in.s_addr >> 24 & 0xFF),
        };

    try {
      return InetAddress.getByAddress(rawAddr);
    } catch (UnknownHostException e) {
      throw new AssertionError();
    }
  }

  /**
   *
   * @param in6
   * @return
   */
  public static InetAddress ntoInetAddress(in6_addr in6) {
    if (in6 == null) {
      return null;
    }

    try {
      return InetAddress.getByAddress(in6.s6_addr);
    } catch (UnknownHostException e) {
      throw new AssertionError();
    }
  }

}
