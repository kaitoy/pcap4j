/*_##########################################################################
  _##
  _##  Copyright (C) 2013 Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import org.pcap4j.packet.IcmpV6CommonPacket.IpV6NeighborDiscoveryOption;
import org.pcap4j.packet.IllegalIpV6NeighborDiscoveryOption;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.namednumber.IpV6NeighborDiscoveryOptionType;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.15
 */
public final class
PropertiesBasedIpV6NeighborDiscoveryOptionFactory
implements PacketFactory<IpV6NeighborDiscoveryOption, IpV6NeighborDiscoveryOptionType> {

  private static final PropertiesBasedIpV6NeighborDiscoveryOptionFactory INSTANCE
    = new PropertiesBasedIpV6NeighborDiscoveryOptionFactory();

  private PropertiesBasedIpV6NeighborDiscoveryOptionFactory() {}

  /**
   *
   * @return the singleton instance of PropertiesBasedIpV6NeighborDiscoveryOptionFactory.
   */
  public static PropertiesBasedIpV6NeighborDiscoveryOptionFactory getInstance() {
    return INSTANCE;
  }

  public IpV6NeighborDiscoveryOption newInstance(
    byte[] rawData, IpV6NeighborDiscoveryOptionType type
  ) {
    if (type == null) {
      throw new NullPointerException(" type: " + type);
    }

    Class<? extends IpV6NeighborDiscoveryOption> dataClass
      = PacketFactoryPropertiesLoader.getInstance().getIpV6NeighborDiscoveryOptionClass(type);
    return newInstance(rawData, dataClass);
  }

  public IpV6NeighborDiscoveryOption newInstance(byte[] rawData) {
    Class<? extends IpV6NeighborDiscoveryOption> dataClass
      = PacketFactoryPropertiesLoader.getInstance().getUnknownIpV6NeighborDiscoveryOptionClass();
    return newInstance(rawData, dataClass);
  }

  /**
   *
   * @param rawData
   * @param dataClass
   * @return a new IpV6NeighborDiscoveryOption object.
   */
  public IpV6NeighborDiscoveryOption newInstance(
    byte[] rawData, Class<? extends IpV6NeighborDiscoveryOption> dataClass
  ) {
    if (rawData == null || dataClass == null) {
      StringBuilder sb = new StringBuilder(50);
      sb.append("rawData: ")
        .append(rawData)
        .append(" dataClass: ")
        .append(dataClass);
      throw new NullPointerException(sb.toString());
    }

    try {
      Method newInstance = dataClass.getMethod("newInstance", byte[].class);
      return (IpV6NeighborDiscoveryOption)newInstance.invoke(null, rawData);
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
        return IllegalIpV6NeighborDiscoveryOption.newInstance(rawData);
      }
      throw new IllegalStateException(e.getTargetException());
    }
  }

}
