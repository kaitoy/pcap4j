/*_##########################################################################
  _##
  _##  Copyright (C) 2011  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.PropertiesLoader;

class PacketPropertiesLoader {

  private static final String KEY_PREFIX
    = PacketPropertiesLoader.class.getPackage().getName();
  public static final String PACKET_PROPERTIES_NAME_KEY
    = KEY_PREFIX + "packet.properties";
  private static final PacketPropertiesLoader INSTANCE
    = new PacketPropertiesLoader();

  private PropertiesLoader loader
    = new PropertiesLoader(
        System.getProperty(
          PACKET_PROPERTIES_NAME_KEY,
          KEY_PREFIX.replace('.', '/') + "/packet.properties"
        )
      );

  private PacketPropertiesLoader() {}

  public static PacketPropertiesLoader getInstance() {
    return INSTANCE;
  }

  public boolean isEnabledIcmpChecksumVaridation() {
    return loader.getBoolean(
             KEY_PREFIX + ".icmp.enableChecksumValidation",
             Boolean.FALSE
           ).booleanValue();
  }

  public boolean isEnabledIcmpChecksumVerification() {
    return loader.getBoolean(
             KEY_PREFIX + ".icmp.enableChecksumVerification",
             Boolean.FALSE
           ).booleanValue();
  }

  public boolean isEnabledIpv4ChecksumVaridation() {
    return loader.getBoolean(
             KEY_PREFIX + ".ipv4.enableChecksumValidation",
             Boolean.FALSE
           ).booleanValue();
  }

  public boolean isEnabledIpv4ChecksumVerification() {
    return loader.getBoolean(
             KEY_PREFIX + ".ipv4.enableChecksumVerification",
             Boolean.FALSE
           ).booleanValue();
  }

  public boolean isEnabledUdpChecksumVaridation() {
    return loader.getBoolean(
             KEY_PREFIX + ".udp.enableChecksumValidation",
             Boolean.FALSE
           ).booleanValue();
  }

  public boolean isEnabledUdpChecksumVerification() {
    return loader.getBoolean(
             KEY_PREFIX + ".udp.enableChecksumVerification",
             Boolean.FALSE
           ).booleanValue();
  }

  public Class<? extends Packet> getAnonymousPacketClass() {
    return loader.<Packet>getClass(
             KEY_PREFIX + ".anonymous",
             AnonymousPacket.class
           );
  }

  public boolean isExtendedNewPacketByDlt() {
    return loader.getBoolean(
             KEY_PREFIX + ".PacketFactory.extendNewPacketByDlt",
             Boolean.FALSE
           );
  }

  public Class<? extends Packet> getPacketClassByDlt(Integer dlt) {
    return loader.<Packet>getClass(
             KEY_PREFIX + ".DLT." + dlt,
             getAnonymousPacketClass()
           );
  }

  public boolean isExtendedNewPacketByEtherType() {
    return loader.getBoolean(
             KEY_PREFIX + ".PacketFactory.extendNewPacketByEtherType",
             Boolean.FALSE
           );
  }

  public Class<? extends Packet> getPacketClassByEtherType(Short etherType) {
    return loader.<Packet>getClass(
             KEY_PREFIX + ".EtherType."
               + ByteArrays.toHexString(etherType, "").toLowerCase(),
             getAnonymousPacketClass()
           );
  }

  public boolean isExtendedNewPacketByIPNumber() {
    return loader.getBoolean(
             KEY_PREFIX + ".PacketFactory.extendNewPacketByIPNumber",
             Boolean.FALSE
           );
  }

  public Class<? extends Packet> getPacketClassByIPNumber(Byte ipNumber) {
    return loader.<Packet>getClass(
             KEY_PREFIX + ".IPNumber." + String.valueOf(ipNumber & 0xFF),
             getAnonymousPacketClass()
           );
  }

}
