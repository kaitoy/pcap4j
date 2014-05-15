/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import org.pcap4j.packet.IpV4Packet.IpV4Tos;
import org.pcap4j.packet.namednumber.NA;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.14
 */
public final class PropertiesBasedIpV4TosFactory
implements PacketFactory<IpV4Tos, NA> {

  private static final PropertiesBasedIpV4TosFactory INSTANCE
    = new PropertiesBasedIpV4TosFactory();

  private PropertiesBasedIpV4TosFactory() {}

  /**
   *
   * @return the singleton instance of PropertiesBasedIpV4TosFactory
   */
  public static PropertiesBasedIpV4TosFactory getInstance() { return INSTANCE; }

  @Override
  @Deprecated
  public IpV4Tos newInstance(byte[] rawData, NA number) {
    return newInstance(rawData);
  }

  @Override
  public IpV4Tos newInstance(byte[] rawData) {
    return newInstance(rawData, getTargetClass());
  }

  /**
   *
   * @param rawData
   * @param tosClass
   * @return a new IpV4Tos object.
   */
  public IpV4Tos newInstance(byte[] rawData, Class<? extends IpV4Tos> tosClass) {
    if (rawData == null || tosClass == null) {
      StringBuilder sb = new StringBuilder(50);
      sb.append("rawData: ")
        .append(rawData)
        .append(" tosClass: ")
        .append(tosClass);
      throw new NullPointerException(sb.toString());
    }
    if (rawData.length == 0) {
      throw new IllegalArgumentException("rawData is empty.");
    }

    try {
      Method newInstance = tosClass.getMethod("newInstance", byte.class);
      return (IpV4Tos)newInstance.invoke(null, rawData[0]);
    } catch (SecurityException e) {
      throw new IllegalStateException(e);
    } catch (NoSuchMethodException e) {
      throw new IllegalStateException(e);
    } catch (IllegalArgumentException e) {
      throw new IllegalStateException(e);
    } catch (IllegalAccessException e) {
      throw new IllegalStateException(e);
    } catch (InvocationTargetException e) {
      throw new IllegalStateException(e.getTargetException());
    }
  }

  @Override
  @Deprecated
  public Class<? extends IpV4Tos> getTargetClass(NA number) {
    return getTargetClass();
  }

  @Override
  public Class<? extends IpV4Tos> getTargetClass() {
    return PacketFactoryPropertiesLoader.getInstance().getIpV4TosClass();
  }

}
