/*_##########################################################################
  _##
  _##  Copyright (C) 2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import org.pcap4j.packet.IllegalPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.NamedNumber;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.14
 */
public final class PropertiesBasedPacketFactory
implements PacketFactory<Packet, NamedNumber<?>> {

  private static final PropertiesBasedPacketFactory INSTANCE
    = new PropertiesBasedPacketFactory();

  private PropertiesBasedPacketFactory() {};

  /**
   *
   * @return the singleton instance of PropertiesBasedPacketFactory.
   */
  public static PropertiesBasedPacketFactory getInstance() { return INSTANCE; }


  public Packet newInstance(byte[] rawData, NamedNumber<?> number) {
    if (number == null) {
      throw new NullPointerException(" number: " + number);
    }

    Class<? extends Packet> packetClass
      = PacketFactoryPropertiesLoader.getInstance().getPacketClass(number);
    return newInstance(rawData, packetClass);
  }

  public Packet newInstance(byte[] rawData) {
    Class<? extends Packet> packetClass
      = PacketFactoryPropertiesLoader.getInstance().getUnknownPacketClass();
    return newInstance(rawData, packetClass);
  }

  /**
   *
   * @param rawData
   * @param packetClass
   * @return a new Packet object.
   */
  public Packet newInstance(
    byte[] rawData, Class<? extends Packet> packetClass
  ) {
    if (rawData == null || packetClass == null) {
      StringBuilder sb = new StringBuilder(50);
      sb.append("rawData: ")
        .append(rawData)
        .append(" packetClass: ")
        .append(packetClass);
      throw new NullPointerException(sb.toString());
    }

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
      if (e.getTargetException() instanceof IllegalRawDataException) {
        return IllegalPacket.newPacket(rawData);
      }
      throw new IllegalStateException(e);
    }
  }

}
