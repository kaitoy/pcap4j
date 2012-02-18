/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import org.pcap4j.packet.namedvalue.DataLinkType;
import org.pcap4j.packet.namedvalue.EtherType;
import org.pcap4j.packet.namedvalue.IpNumber;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public class PacketFactory {

  private PacketFactory() { throw new AssertionError(); }

  /**
   *
   * @param rawData
   * @param packetClass
   * @return
   */
  public static Packet newPacket(byte[] rawData, Class<? extends Packet> packetClass) {
    try {
      Method newPacket = packetClass.getMethod("newPacket", byte[].class);
      return (Packet)newPacket.invoke(null, rawData);
    } catch (SecurityException e) {
      throw new IllegalStateException(e);
    } catch (NoSuchMethodException e) {
      throw new IllegalStateException(e);
    } catch (IllegalArgumentException e) {
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
  public static Packet newPacketByDlt(byte[] rawData, Integer dlt) {
    if (PacketPropertiesLoader.getInstance().isExtendedNewPacketByDlt()) {
      Class<? extends Packet> packetClass
        = PacketPropertiesLoader.getInstance().getPacketClassByDlt(dlt);
      return newPacket(rawData, packetClass);
    }
    else {
      if (dlt.equals(DataLinkType.EN10MB.value())) {
        return EthernetPacket.newPacket(rawData);
      }
      else {
        return AnonymousPacket.newPacket(rawData);
      }
    }
  }

  /**
   *
   * @param rawData
   * @param etherType
   * @return
   */
  public static Packet newPacketByEtherType(byte[] rawData, Short etherType) {
    if (PacketPropertiesLoader.getInstance().isExtendedNewPacketByEtherType()) {
      Class<? extends Packet> packetClass
        = PacketPropertiesLoader.getInstance()
            .getPacketClassByEtherType(etherType);
      return newPacket(rawData, packetClass);
    }
    else {
      if (etherType.equals(EtherType.IPV4.value())) {
        return IpV4Packet.newPacket(rawData);
      }
      else if (etherType.equals(EtherType.ARP.value())) {
        return ArpPacket.newPacket(rawData);
      }
      else if (etherType.equals(EtherType.DOT1Q_VLAN_TAGGED_FRAMES.value())) {
        return Dot1qVlanTaggedPacket.newPacket(rawData);
      }
      else if (etherType.equals(EtherType.IPV6.value())) {
        // TODO support IPv6
        return AnonymousPacket.newPacket(rawData);
      }
      else {
        return AnonymousPacket.newPacket(rawData);
      }
    }
  }

  /**
   *
   * @param rawData
   * @param ipNumber
   * @return
   */
  public static Packet newPacketByIpNumber(byte[] rawData, Byte ipNumber) {
    if (PacketPropertiesLoader.getInstance().isExtendedNewPacketByIPNumber()) {
      Class<? extends Packet> packetClass
        = PacketPropertiesLoader.getInstance().getPacketClassByIPNumber(ipNumber);
      return newPacket(rawData, packetClass);
    }
    else {
      if (ipNumber.equals(IpNumber.UDP.value())) {
        return UdpPacket.newPacket(rawData);
      }
      else if (ipNumber.equals(IpNumber.ICMP_V4.value())) {
        return IcmpV4Packet.newPacket(rawData);
      }
      else if (ipNumber.equals(IpNumber.TCP.value())) {
        // TODO support TCP
        return AnonymousPacket.newPacket(rawData);
      }
      else {
        return AnonymousPacket.newPacket(rawData);
      }
    }
  }

  /**
   *
   * @param rawData
   * @param port
   * @return
   */
  public static Packet newPacketByPort(byte[] rawData, short port) {
    if (PacketPropertiesLoader.getInstance().isExtendedNewPacketByPort()) {
      Class<? extends Packet> packetClass
        = PacketPropertiesLoader.getInstance().getPacketClassByPort(port);
      return newPacket(rawData, packetClass);
    }
    else {
      return AnonymousPacket.newPacket(rawData);
    }
  }

}
