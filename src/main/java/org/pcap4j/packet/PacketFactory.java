/*_##########################################################################
  _##
  _##  Copyright (C) 2011  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import org.pcap4j.packet.namedvalue.DataLinkType;
import org.pcap4j.packet.namedvalue.EtherType;
import org.pcap4j.packet.namedvalue.IpNumber;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public class PacketFactory {

  private static final PacketFactory INSTANCE = new PacketFactory();

  private PacketFactory() {}

  /**
   *
   * @return
   */
  public static PacketFactory getInstance() {
    return INSTANCE;
  }

  /**
   *
   * @param rawData
   * @param packetClass
   * @return
   */
  public Packet newPacket(byte[] rawData, Class<? extends Packet> packetClass) {
    try {
      Constructor<? extends Packet> constructor
        = packetClass.getConstructor(byte[].class);
      return constructor.newInstance(rawData);
    } catch (SecurityException e) {
      throw new IllegalStateException(e);
    } catch (NoSuchMethodException e) {
      throw new IllegalStateException(e);
    } catch (IllegalArgumentException e) {
      throw new IllegalStateException(e);
    } catch (InstantiationException e) {
      throw new IllegalStateException(e);
    } catch (IllegalAccessException e) {
      throw new IllegalStateException(e);
    } catch (InvocationTargetException e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   *
   * @param rawData
   * @param dlt
   * @return
   */
  public Packet newPacketByDlt(byte[] rawData, Integer dlt) {
    if (PacketPropertiesLoader.getInstance().isExtendedNewPacketByDlt()) {
      Class<? extends Packet> packetClass
        = PacketPropertiesLoader.getInstance().getPacketClassByDlt(dlt);
      return newPacket(rawData, packetClass);
    }
    else {
      if (dlt.equals(DataLinkType.EN10MB.value())) {
        return new EthernetPacket(rawData);
      }
      else {
        return new AnonymousPacket(rawData);
      }
    }
  }

  /**
   *
   * @param rawData
   * @param etherType
   * @return
   */
  public Packet newPacketByEtherType(byte[] rawData, Short etherType) {
    if (PacketPropertiesLoader.getInstance().isExtendedNewPacketByEtherType()) {
      Class<? extends Packet> packetClass
        = PacketPropertiesLoader.getInstance().getPacketClassByEtherType(etherType);
      return newPacket(rawData, packetClass);
    }
    else {
      if (etherType.equals(EtherType.IPV4.value())) {
        return new IpV4Packet(rawData);
      }
      else if (etherType.equals(EtherType.ARP.value())) {
        return new ArpPacket(rawData);
      }
      else if (etherType.equals(EtherType.IPV6.value())) {
        // TODO support IPv6
        return new AnonymousPacket(rawData);
      }
      else {
        return new AnonymousPacket(rawData);
      }
    }
  }

  /**
   *
   * @param rawData
   * @param ipNumber
   * @return
   */
  public Packet newPacketByIpNumber(byte[] rawData, Byte ipNumber) {
    if (PacketPropertiesLoader.getInstance().isExtendedNewPacketByIPNumber()) {
      Class<? extends Packet> packetClass
        = PacketPropertiesLoader.getInstance().getPacketClassByIPNumber(ipNumber);
      return newPacket(rawData, packetClass);
    }
    else {
      if (ipNumber.equals(IpNumber.UDP.value())) {
        return new UdpPacket(rawData);
      }
      else if (ipNumber.equals(IpNumber.ICMP_V4.value())) {
        return new IcmpV4Packet(rawData);
      }
      else if (ipNumber.equals(IpNumber.TCP.value())) {
        // TODO support TCP
        return new AnonymousPacket(rawData);
      }
      else {
        return new AnonymousPacket(rawData);
      }
    }
  }

}
