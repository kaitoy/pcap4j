/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2014  Kaito Yamada
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

  @Override
  public IpV6NeighborDiscoveryOption newInstance(
    byte[] rawData, int offset, int length, IpV6NeighborDiscoveryOptionType type
  ) {
    return newInstance(rawData, offset, length, getTargetClass(type));
  }

  @Override
  public IpV6NeighborDiscoveryOption newInstance(byte[] rawData, int offset, int length) {
    return newInstance(rawData, offset, length, getTargetClass());
  }

  /**
   *
   * @param rawData
   * @param offset
   * @param length
   * @param dataClass
   * @return a new IpV6NeighborDiscoveryOption object.
   * @throws IllegalStateException
   * @throws IllegalArgumentException
   * @throws NullPointerException
   */
  public IpV6NeighborDiscoveryOption newInstance(
    byte[] rawData, int offset, int length, Class<? extends IpV6NeighborDiscoveryOption> dataClass
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
      Method newInstance = dataClass.getMethod("newInstance", byte[].class, int.class, int.class);
      return (IpV6NeighborDiscoveryOption)newInstance.invoke(null, rawData, offset, length);
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
        return IllegalIpV6NeighborDiscoveryOption.newInstance(rawData, offset, length);
      }
      throw new IllegalArgumentException(e);
    }
  }

  @Override
  public Class<? extends IpV6NeighborDiscoveryOption>
  getTargetClass(IpV6NeighborDiscoveryOptionType type) {
    if (type == null) {
      throw new NullPointerException("type: " + type);
    }
    return PacketFactoryPropertiesLoader.getInstance()
             .getIpV6NeighborDiscoveryOptionClass(type);
  }

  @Override
  public Class<? extends IpV6NeighborDiscoveryOption> getTargetClass() {
    return PacketFactoryPropertiesLoader.getInstance()
             .getUnknownIpV6NeighborDiscoveryOptionClass();
  }

}
