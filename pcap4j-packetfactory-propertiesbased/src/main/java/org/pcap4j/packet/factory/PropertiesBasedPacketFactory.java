/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Pcap4J.org
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
implements PacketFactory<Packet, NamedNumber<?, ?>> {

  private static final PropertiesBasedPacketFactory INSTANCE
    = new PropertiesBasedPacketFactory();

  private PropertiesBasedPacketFactory() {};

  /**
   *
   * @return the singleton instance of PropertiesBasedPacketFactory.
   */
  public static PropertiesBasedPacketFactory getInstance() { return INSTANCE; }


  @Override
  public Packet newInstance(byte[] rawData, int offset, int length, NamedNumber<?, ?> number) {
    return newInstance(rawData, offset, length, getTargetClass(number));
  }

  @Override
  public Packet newInstance(byte[] rawData, int offset, int length) {
    return newInstance(rawData, offset, length, getTargetClass());
  }

  /**
   *
   * @param rawData
   * @param offset
   * @param length
   * @param packetClass
   * @return a new Packet object.
   * @throws IllegalStateException
   * @throws IllegalArgumentException
   * @throws NullPointerException
   */
  public Packet newInstance(
    byte[] rawData, int offset, int length, Class<? extends Packet> packetClass
  ) {
    if (rawData == null || packetClass == null) {
      StringBuilder sb = new StringBuilder(40);
      sb.append("rawData: ")
        .append(rawData)
        .append(" packetClass: ")
        .append(packetClass);
      throw new NullPointerException(sb.toString());
    }

    try {
      Method newPacket = packetClass.getMethod("newPacket", byte[].class, int.class, int.class);
      return (Packet)newPacket.invoke(null, rawData, offset, length);
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
        return IllegalPacket.newPacket(rawData, offset, length);
      }
      throw new IllegalArgumentException(e);
    }
  }

  @Override
  public Class<? extends Packet> getTargetClass(NamedNumber<?, ?> number) {
    if (number == null) {
      throw new NullPointerException("number: " + number);
    }
    return PacketFactoryPropertiesLoader.getInstance().getPacketClass(number);
  }

  @Override
  public Class<? extends Packet> getTargetClass() {
    return PacketFactoryPropertiesLoader.getInstance().getUnknownPacketClass();
  }

}
