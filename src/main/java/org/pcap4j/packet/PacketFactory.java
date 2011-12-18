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

public class PacketFactory {

  private static final PacketFactory INSTANCE = new PacketFactory();

  private PacketFactory() {}

  public static PacketFactory getInstance() {
    return INSTANCE;
  }

  private Packet newPacket(byte[] rawData, Class<? extends Packet> packetClass) {
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

  public Packet newPacketByDlt(byte[] rawData, Integer dlt) {
    if (PacketPropertiesLoader.getInstance().extendNewPacketByDlt()) {
      Class<? extends Packet> packetClass
        = PacketPropertiesLoader.getInstance().getPacketClassByDlt(dlt);
      return newPacket(rawData, packetClass);
    }
    else {
      if (dlt.equals(DataLinkType.EN10MB)) {
        return new EthernetPacket(rawData);
      }
      else {
        return new AnonymousPacket(rawData);
      }
    }
  }

  public Packet newPacketByEtherType(byte[] rawData, Short etherType) {
    if (PacketPropertiesLoader.getInstance().extendNewPacketByEtherType()) {
      Class<? extends Packet> packetClass
        = PacketPropertiesLoader.getInstance().getPacketClassByEtherType(etherType);
      return newPacket(rawData, packetClass);
    }
    else {
      if (etherType.equals(EtherType.IPV4)) {
        return new IpV4Packet(rawData);
      }
      else if (etherType.equals(EtherType.ARP)) {
        return new ArpPacket(rawData);
      }
      else if (etherType.equals(EtherType.IPV6)) {
        // TODO support IPv6
        return new AnonymousPacket(rawData);
      }
      else {
        return new AnonymousPacket(rawData);
      }
    }
  }

  public Packet newPacketByIpNumber(byte[] rawData, Byte ipNumber) {
    if (PacketPropertiesLoader.getInstance().extendNewPacketByIPNumber()) {
      Class<? extends Packet> packetClass
        = PacketPropertiesLoader.getInstance().getPacketClassByIPNumber(ipNumber);
      return newPacket(rawData, packetClass);
    }
    else {
      if (ipNumber.equals(IpNumber.UDP)) {
        return new UdpPacket(rawData);
      }
      else if (ipNumber.equals(IpNumber.ICMP_V4)) {
        return new IcmpV4Packet(rawData);
      }
      else if (ipNumber.equals(IpNumber.TCP)) {
        // TODO support TCP
        return new AnonymousPacket(rawData);
      }
      else {
        return new AnonymousPacket(rawData);
      }
    }
  }

}
