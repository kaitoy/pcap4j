/*_##########################################################################
  _##
  _##  Copyright (C) 2014-2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j;

import com.sun.jna.Platform;
import org.pcap4j.util.PropertiesLoader;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.0.1
 */
public final class Pcap4jPropertiesLoader {

  private static final String KEY_PREFIX = Pcap4jPropertiesLoader.class.getPackage().getName();

  /** */
  public static final String PCAP4J_PROPERTIES_PATH_KEY = KEY_PREFIX + ".properties";

  /** */
  public static final String AF_INET_KEY = KEY_PREFIX + ".af.inet";

  /** */
  public static final String AF_INET6_KEY = KEY_PREFIX + ".af.inet6";

  /** */
  public static final String AF_PACKET_KEY = KEY_PREFIX + ".af.packet";

  /** */
  public static final String AF_LINK_KEY = KEY_PREFIX + ".af.link";

  /** */
  public static final String DLT_RAW_KEY = KEY_PREFIX + ".dlt.raw";

  private static final int AF_INET_DEFAULT = 2;
  private static final int AF_PACKET_DEFAULT = 17;
  private static final int AF_LINK_DEFAULT = 18;
  private static final int DLT_RAW_DEFAULT = 12;
  private static final int DLT_RAW_OPENBSD = 14;
  private static final int AF_INET6_DEFAULT = 23;
  private static final int AF_INET6_LINUX = 10;
  private static final int AF_INET6_FREEBSD = 28;
  private static final int AF_INET6_MAC = 30;

  private static final Pcap4jPropertiesLoader INSTANCE = new Pcap4jPropertiesLoader();

  private PropertiesLoader loader =
      new PropertiesLoader(
          System.getProperty(
              PCAP4J_PROPERTIES_PATH_KEY, KEY_PREFIX.replace('.', '/') + "/pcap4j.properties"),
          true,
          true);

  private Pcap4jPropertiesLoader() {}

  /** @return the singleton instance of Pcap4jPropertiesLoader. */
  public static Pcap4jPropertiesLoader getInstance() {
    return INSTANCE;
  }

  /** @return address family number for IPv4 addresses. Never null. */
  public Integer getAfInet() {
    return loader.getInteger(AF_INET_KEY, AF_INET_DEFAULT);
  }

  /** @return address family numbers for IPv6 addresses. Never null. */
  public Integer getAfInet6() {
    return loader.getInteger(AF_INET6_KEY, getDefaultAfInet6());
  }

  /**
   * For Linux
   *
   * @return address family numbers for link layer addresses. Never null.
   */
  public Integer getAfPacket() {
    return loader.getInteger(AF_PACKET_KEY, AF_PACKET_DEFAULT);
  }

  /**
   * For BSD including Mac OS X
   *
   * @return address family numbers for link layer addresses. Never null.
   */
  public Integer getAfLink() {
    return loader.getInteger(AF_LINK_KEY, AF_LINK_DEFAULT);
  }

  /**
   * DLT_RAW
   *
   * @return the value of DLT_RAW. Never null.
   */
  public Integer getDltRaw() {
    return loader.getInteger(DLT_RAW_KEY, getDefaultDltRaw());
  }

  /** @return The default address family for IPv6 addresses (platform specific) */
  private int getDefaultAfInet6() {
    switch (Platform.getOSType()) {
      case Platform.MAC:
        return AF_INET6_MAC;
      case Platform.FREEBSD:
      case Platform.KFREEBSD:
        return AF_INET6_FREEBSD;
      case Platform.LINUX:
      case Platform.ANDROID:
        return AF_INET6_LINUX;
      default:
        return AF_INET6_DEFAULT;
    }
  }

  /** @return The default value for DLT_RAW (platform specific) */
  private int getDefaultDltRaw() {
    switch (Platform.getOSType()) {
      case Platform.OPENBSD:
        return DLT_RAW_OPENBSD;
      default:
        return DLT_RAW_DEFAULT;
    }
  }
}
