/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory.propertiesbased;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import org.pcap4j.packet.IpV6Packet.IpV6TrafficClass;
import org.pcap4j.packet.factory.PacketFactory;
import org.pcap4j.packet.namednumber.NotApplicable;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.14
 */
public final class PropertiesBasedIpV6TrafficClassFactory
    implements PacketFactory<IpV6TrafficClass, NotApplicable> {

  private static final PropertiesBasedIpV6TrafficClassFactory INSTANCE =
      new PropertiesBasedIpV6TrafficClassFactory();

  private PropertiesBasedIpV6TrafficClassFactory() {}

  /** @return the singleton instance of PropertiesBasedIpV6TrafficClassFactory. */
  public static PropertiesBasedIpV6TrafficClassFactory getInstance() {
    return INSTANCE;
  }

  @Override
  @Deprecated
  public IpV6TrafficClass newInstance(
      byte[] rawData, int offset, int length, NotApplicable number) {
    return newInstance(rawData, offset, length);
  }

  @Override
  public IpV6TrafficClass newInstance(byte[] rawData, int offset, int length) {
    return newInstance(rawData, offset, length, getTargetClass());
  }

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @param clazz clazz
   * @return a new IpV6TrafficClass object.
   * @throws IllegalStateException if an access to the newInstance method of the clazz fails.
   * @throws IllegalArgumentException if an exception is thrown by newInstance method of the clazz.
   * @throws NullPointerException if any of arguments are null.
   */
  public IpV6TrafficClass newInstance(
      byte[] rawData, int offset, int length, Class<? extends IpV6TrafficClass> clazz) {
    ByteArrays.validateBounds(rawData, offset, length);
    if (clazz == null) {
      throw new NullPointerException("clazz is null.");
    }

    try {
      Method newInstance = clazz.getMethod("newInstance", byte.class);
      return (IpV6TrafficClass) newInstance.invoke(null, rawData[offset]);
    } catch (SecurityException e) {
      throw new IllegalStateException(e);
    } catch (NoSuchMethodException e) {
      throw new IllegalStateException(e);
    } catch (IllegalArgumentException e) {
      throw new IllegalStateException(e);
    } catch (IllegalAccessException e) {
      throw new IllegalStateException(e);
    } catch (InvocationTargetException e) {
      throw new IllegalArgumentException(e);
    }
  }

  @Override
  @Deprecated
  public Class<? extends IpV6TrafficClass> getTargetClass(NotApplicable number) {
    return getTargetClass();
  }

  @Override
  public Class<? extends IpV6TrafficClass> getTargetClass() {
    return PacketFactoryPropertiesLoader.getInstance().getIpV6TrafficClassClass();
  }
}
