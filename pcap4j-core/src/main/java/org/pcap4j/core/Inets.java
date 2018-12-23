/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2016  Pcap4J.org
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

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public final class Inets {

  /**
   * Unspecified address family. This value is defined in <code>&lt;sys/socket.h&gt;</code> as 0.
   */
  public static final short AF_UNSPEC = 0;

  /**
   * Address family for IPv4. This value needs to be the same as AF_INET defined in <code>
   * &lt;sys/socket.h&gt;</code>. This value may vary depending on OS. This value is set to 2 by
   * default and can be changed by setting the property <code>org.pcap4j.af.inet</code> (system
   * property or pcap4j-core.jar/org/pcap4j/pcap4j.properties).
   *
   * @see org.pcap4j.Pcap4jPropertiesLoader
   */
  public static final short AF_INET;

  /**
   * Address family for IPv6. This value needs to be the same as AF_INET6 defined in <code>
   * &lt;sys/socket.h&gt;</code>. This value varies depending on OS. By default, this value is set
   * to 30 on Mac OS X, 28 on FreeBSD, 10 on Linux, and 23 on the others. This value can be changed
   * by setting the property <code>org.pcap4j.af.inet6</code> (system property or
   * pcap4j-core.jar/org/pcap4j/pcap4j.properties).
   *
   * @see org.pcap4j.Pcap4jPropertiesLoader
   */
  public static final short AF_INET6;

  /**
   * Address family for low level packet interface. This value needs to be the same as AF_PACKET
   * defined in <code>&lt;sys/socket.h&gt;</code>. This value may vary depending on OS. This value
   * is set to 17 by default and can be changed by setting the property <code>org.pcap4j.af.packet
   * </code> (system property or pcap4j-core.jar/org/pcap4j/pcap4j.properties).
   *
   * @see org.pcap4j.Pcap4jPropertiesLoader
   */
  public static final short AF_PACKET;

  /**
   * Address family for link layer interface. This value needs to be the same as AF_LINK defined in
   * <code>&lt;sys/socket.h&gt;</code>. This value may vary depending on OS. This value is set to 18
   * by default and can be changed by setting the property <code>org.pcap4j.af.link</code> (system
   * property or pcap4j-core.jar/org/pcap4j/pcap4j.properties).
   *
   * @see org.pcap4j.Pcap4jPropertiesLoader
   */
  public static final short AF_LINK;

  static {
    AF_INET = Pcap4jPropertiesLoader.getInstance().getAfInet().shortValue();
    AF_INET6 = Pcap4jPropertiesLoader.getInstance().getAfInet6().shortValue();
    AF_PACKET = Pcap4jPropertiesLoader.getInstance().getAfPacket().shortValue();
    AF_LINK = Pcap4jPropertiesLoader.getInstance().getAfLink().shortValue();
  }

  private Inets() {
    throw new AssertionError();
  }

  static Inet4Address ntoInetAddress(in_addr in) {
    if (in == null) {
      return null;
    }
    return itoInetAddress(in.s_addr);
  }

  static Inet4Address itoInetAddress(int i) {
    return ByteArrays.getInet4Address(
        ByteArrays.toByteArray(i, NativeMappings.NATIVE_BYTE_ORDER), 0);
  }

  static Inet6Address ntoInetAddress(in6_addr in6) {
    if (in6 == null) {
      return null;
    }

    try {
      return (Inet6Address) InetAddress.getByAddress(in6.s6_addr);
    } catch (UnknownHostException e) {
      throw new AssertionError();
    }
  }
}
