/*_##########################################################################
  _##
  _##  Copyright (C) 2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j;

import org.pcap4j.util.PropertiesLoader;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.0.1
 */
public final class Pcap4jPropertiesLoader {

   private static final String KEY_PREFIX
     = Pcap4jPropertiesLoader.class.getPackage().getName();

   /**
    *
    */
   public static final String PCAP4J_PROPERTIES_PATH_KEY
     = KEY_PREFIX + ".properties";

   /**
    *
    */
   public static final String AF_INET_KEY = KEY_PREFIX + ".af.inet";

   /**
    *
    */
   public static final String AF_INET6_KEY = KEY_PREFIX + ".af.inet6";

   /**
    *
    */
   public static final String AF_PACKET_KEY = KEY_PREFIX + ".af.packet";

   /**
    *
    */
   public static final String AF_LINK_KEY = KEY_PREFIX + ".af.link";

   /**
    *
    */
   public static final String DLT_RAW_KEY = KEY_PREFIX + ".dlt.raw";

   private static final Pcap4jPropertiesLoader INSTANCE = new Pcap4jPropertiesLoader();

   private PropertiesLoader loader
     = new PropertiesLoader(
         System.getProperty(
           PCAP4J_PROPERTIES_PATH_KEY,
           KEY_PREFIX.replace('.', '/') + "/pcap4j.properties"
         ),
         true,
         true
       );

  private Pcap4jPropertiesLoader() {}

  /**
   *
   * @return the singleton instance of Pcap4jPropertiesLoader.
   */
  public static Pcap4jPropertiesLoader getInstance() {
    return INSTANCE;
  }

  /**
   *
   * @return address family number for IPv4 addresses.
   */
  public Integer getAfInet() {
    return loader.getInteger(
             AF_INET_KEY ,
             null
           );
  }

  /**
   *
   * @return address family numbers for IPv6 addresses.
   */
  public Integer getAfInet6() {
    return loader.getInteger(
             AF_INET6_KEY ,
             null
           );
  }

  /**
   * For Linux
   *
   * @return address family numbers for link layer addresses.
   */
  public Integer getAfPacket() {
    return loader.getInteger(
             AF_PACKET_KEY ,
             null
           );
  }

  /**
   * For BSD including Mac OS X
   *
   * @return address family numbers for link layer addresses.
   */
  public Integer getAfLink() {
    return loader.getInteger(
             AF_LINK_KEY ,
             null
           );
  }


  /**
   * DLT_RAW
   *
   * @return the value of DLT_RAW
   */
  public Integer getDltRaw() {
    return loader.getInteger(
             DLT_RAW_KEY ,
             null
           );
  }

}
