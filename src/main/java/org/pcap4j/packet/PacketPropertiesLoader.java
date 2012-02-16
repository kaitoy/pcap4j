/*_##########################################################################
  _##
  _##  Copyright (C) 2011  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.PropertiesLoader;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
class PacketPropertiesLoader {

  private static final String KEY_PREFIX
    = PacketPropertiesLoader.class.getPackage().getName();
  private static final String PACKET_PROPERTIES_PATH_KEY
    = KEY_PREFIX + ".properties";
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

  private static String ICMP_CHECKSUMVARIDATION_KEY
    = KEY_PREFIX + ".icmp.enableChecksumValidation";

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


  private static String ICMP_ENABLECHECKSUMVERIFICATION_KEY
    = KEY_PREFIX + ".icmp.enableChecksumVerification";

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

  private static String IPV4_ENABLECHECKSUMVALIDATION_KEY
    = KEY_PREFIX + ".ipv4.enableChecksumValidation";

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

  private static String IPV4_ENABLECHECKSUMVERIFICATION_KEY
    = KEY_PREFIX + ".ipv4.enableChecksumVerification";

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

  private static String UDP_ENABLECHECKSUMVALIDATION_KEY
    = KEY_PREFIX + ".udp.enableChecksumValidation";

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

  private static String UDP_ENABLECHECKSUMVERIFICATION_KEY
    = KEY_PREFIX + ".udp.enableChecksumVerification";

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

  private static String PACKETFACTORY_ANONYMOUS_KEY
    = KEY_PREFIX + ".PacketFactory.anonymous";

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

  private static String PACKETFACTORY_EXTENDNEWPACKETBYDLT_KEY
    = KEY_PREFIX + ".PacketFactory.extendNewPacketByDlt";

  /**
   *
   * @return
   */
  public boolean isExtendedNewPacketByDlt() {
    return loader.getBoolean(
             PACKETFACTORY_EXTENDNEWPACKETBYDLT_KEY,
             Boolean.FALSE
           );
  }

  private static String PACKETFACTORY_DLT_KEY
    = KEY_PREFIX + ".PacketFactory.DLT.";

  /**
   *
   * @param dlt
   * @return
   */
  public Class<? extends Packet> getPacketClassByDlt(Integer dlt) {
    return loader.<Packet>getClass(
             PACKETFACTORY_DLT_KEY + dlt,
             getAnonymousPacketClass()
           );
  }

  private static String PACKETFACTORY_EXTENDNEWPACKETBYETHERTYPE_KEY
    = KEY_PREFIX + ".PacketFactory.extendNewPacketByEtherType";

  /**
   *
   * @return
   */
  public boolean isExtendedNewPacketByEtherType() {
    return loader.getBoolean(
             PACKETFACTORY_EXTENDNEWPACKETBYETHERTYPE_KEY,
             Boolean.FALSE
           );
  }

  private static String PACKETFACTORY_ETHERTYPE_KEY
    = KEY_PREFIX + ".PacketFactory.EtherType.";

  /**
   *
   * @param etherType
   * @return
   */
  public Class<? extends Packet> getPacketClassByEtherType(Short etherType) {
    return loader.<Packet>getClass(
             PACKETFACTORY_ETHERTYPE_KEY
               + ByteArrays.toHexString(etherType, "").toLowerCase(),
             getAnonymousPacketClass()
           );
  }

  private static String PACKETFACTORY_EXTENDNEWPACKETBYIPNUMBER_KEY
    = KEY_PREFIX + ".PacketFactory.extendNewPacketByIPNumber";

  /**
   *
   * @return
   */
  public boolean isExtendedNewPacketByIPNumber() {
    return loader.getBoolean(
             PACKETFACTORY_EXTENDNEWPACKETBYIPNUMBER_KEY,
             Boolean.FALSE
           );
  }

  private static String PACKETFACTORY_IPNUMBER_KEY
    = KEY_PREFIX + ".PacketFactory.IPNumber.";

  /**
   *
   * @param ipNumber
   * @return
   */
  public Class<? extends Packet> getPacketClassByIPNumber(Byte ipNumber) {
    return loader.<Packet>getClass(
             PACKETFACTORY_IPNUMBER_KEY + String.valueOf(ipNumber & 0xFF),
             getAnonymousPacketClass()
           );
  }

  private static String PACKETFACTORY_EXTENDNEWPACKETBYPORT_KEY
    = KEY_PREFIX + ".PacketFactory.extendNewPacketByPort";

  /**
   *
   * @return
   */
  public boolean isExtendedNewPacketByPort() {
    return loader.getBoolean(
             PACKETFACTORY_EXTENDNEWPACKETBYPORT_KEY,
             Boolean.FALSE
           );
  }

  private static String PACKETFACTORY_PORT_KEY
    = KEY_PREFIX + ".PacketFactory.port.";

  /**
   *
   * @param port
   * @return
   */
  public Class<? extends Packet> getPacketClassByPort(short port) {
    return loader.<Packet>getClass(
             PACKETFACTORY_PORT_KEY + String.valueOf(port & 0xFFFF),
             getAnonymousPacketClass()
           );
  }

}
