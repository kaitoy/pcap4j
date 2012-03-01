/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import org.pcap4j.packet.namednumber.NamedNumber;
import org.pcap4j.util.PropertiesLoader;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public final class PacketPropertiesLoader {

  private static final String KEY_PREFIX
    = PacketPropertiesLoader.class.getPackage().getName();

  /**
   *
   */
  public static final String PACKET_PROPERTIES_PATH_KEY
    = KEY_PREFIX + ".properties";

  /**
   *
   */
  public static final String ICMP_CHECKSUMVARIDATION_KEY
    = KEY_PREFIX + ".icmp.enableChecksumValidation";

  /**
   *
   */
  public static final String ICMP_ENABLECHECKSUMVERIFICATION_KEY
    = KEY_PREFIX + ".icmp.enableChecksumVerification";

  /**
   *
   */
  public static final String IPV4_ENABLECHECKSUMVALIDATION_KEY
    = KEY_PREFIX + ".ipv4.enableChecksumValidation";

  /**
   *
   */
  public static final String IPV4_ENABLECHECKSUMVERIFICATION_KEY
    = KEY_PREFIX + ".ipv4.enableChecksumVerification";

  /**
   *
   */
  public static final String UDP_ENABLECHECKSUMVERIFICATION_KEY
    = KEY_PREFIX + ".udp.enableChecksumVerification";

  /**
   *
   */
  public static final String UDP_ENABLECHECKSUMVALIDATION_KEY
    = KEY_PREFIX + ".udp.enableChecksumValidation";

  /**
   *
   */
  public static final String PACKETFACTORY_ANONYMOUS_KEY
    = KEY_PREFIX + ".PacketFactory.anonymousPacketClass";

  /**
   *
   */
  public static final String PACKET_FACTORY_KEY_BASE
    = KEY_PREFIX + ".PacketFactory.for.";

  /**
   *
   */
  public static final String PACKET_CLASS_KEY_BASE
    = KEY_PREFIX + ".PacketFactory.packetClass.for.";

  private static final PacketPropertiesLoader INSTANCE
    = new PacketPropertiesLoader();

  private PropertiesLoader loader
    = new PropertiesLoader(
        System.getProperty(
          PACKET_PROPERTIES_PATH_KEY,
          KEY_PREFIX.replace('.', '/') + "/packet.properties"
        ),
        true,
        true
      );

  private PacketPropertiesLoader() {}

  /**
   *
   * @return
   */
  public static PacketPropertiesLoader getInstance() {
    return INSTANCE;
  }

  /**
   *
   * @return
   */
  public boolean isEnabledIcmpChecksumVaridation() {
    return loader.getBoolean(
             ICMP_CHECKSUMVARIDATION_KEY,
             Boolean.FALSE
           ).booleanValue();
  }

  /**
   *
   * @return
   */
  public boolean isEnabledIcmpChecksumVerification() {
    return loader.getBoolean(
             ICMP_ENABLECHECKSUMVERIFICATION_KEY,
             Boolean.FALSE
           ).booleanValue();
  }

  /**
   *
   * @return
   */
  public boolean isEnabledIpv4ChecksumVaridation() {
    return loader.getBoolean(
             IPV4_ENABLECHECKSUMVALIDATION_KEY,
             Boolean.FALSE
           ).booleanValue();
  }

  /**
   *
   * @return
   */
  public boolean isEnabledIpv4ChecksumVerification() {
    return loader.getBoolean(
             IPV4_ENABLECHECKSUMVERIFICATION_KEY,
             Boolean.FALSE
           ).booleanValue();
  }

  /**
   *
   * @return
   */
  public boolean isEnabledUdpChecksumVaridation() {
    return loader.getBoolean(
             UDP_ENABLECHECKSUMVALIDATION_KEY,
             Boolean.FALSE
           ).booleanValue();
  }

  /**
   *
   * @return
   */
  public boolean isEnabledUdpChecksumVerification() {
    return loader.getBoolean(
             UDP_ENABLECHECKSUMVERIFICATION_KEY,
             Boolean.FALSE
           ).booleanValue();
  }

  /**
   *
   * @return
   */
  public Class<? extends Packet> getAnonymousPacketClass() {
    return loader.<Packet>getClass(
             PACKETFACTORY_ANONYMOUS_KEY,
             AnonymousPacket.class
           );
  }

  /**
   *
   * @param clazz
   * @return
   */
  public Class<? extends PacketFactory> getPacketFactoryImplClass(
    Class<? extends NamedNumber<?>> clazz
  ) {
    return loader.<PacketFactory>getClass(
             PACKET_FACTORY_KEY_BASE + clazz.getName(),
             DefaultPacketFactory.class
           );
  }

  /**
   *
   * @param number
   * @return
   */
  public <T extends NamedNumber<?>> Class<? extends Packet> getPacketClass(T number) {
    StringBuilder sb = new StringBuilder(100);
    String key = sb.append(PACKET_CLASS_KEY_BASE)
                   .append(number.getClass().getName())
                   .append(".")
                   .append(number.valueAsString())
                   .toString();
    return loader.<Packet>getClass(
             key,
             getAnonymousPacketClass()
           );
  }

}
