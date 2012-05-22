/*_##########################################################################
  _##
  _##  Copyright (C) 2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.PacketFactory;
import org.pcap4j.packet.PacketPropertiesLoader;
import org.pcap4j.packet.namednumber.NamedNumber;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.8
 */
public final class DynamicPacketFactory implements PacketFactory {

  private static final DynamicPacketFactory INSTANCE
    = new DynamicPacketFactory();

  private DynamicPacketFactory() {};

  /**
   *
   * @return
   */
  public static DynamicPacketFactory getInstance() { return INSTANCE; }

  public Packet newPacket(byte[] rawData, NamedNumber<?> number) {
    if (rawData == null || number == null) {
      throw new NullPointerException(
                  "rawData: " + rawData + " number: " + number
                );
    }

    Class<? extends Packet> packetClass
      = PacketPropertiesLoader.getInstance().getPacketClass(number);
    return newPacket(rawData, packetClass);
  }

  /**
   *
   * @param rawData
   * @param packetClass
   * @return
   */
  public Packet newPacket(byte[] rawData, Class<? extends Packet> packetClass) {
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

}
