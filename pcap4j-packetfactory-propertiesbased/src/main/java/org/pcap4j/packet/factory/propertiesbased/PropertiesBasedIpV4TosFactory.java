/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory.propertiesbased;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import org.pcap4j.packet.IpV4Packet.IpV4Tos;
import org.pcap4j.packet.factory.PacketFactory;
import org.pcap4j.packet.namednumber.NotApplicable;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.14
 */
public final class PropertiesBasedIpV4TosFactory implements PacketFactory<IpV4Tos, NotApplicable> {

  private static final PropertiesBasedIpV4TosFactory INSTANCE = new PropertiesBasedIpV4TosFactory();

  private PropertiesBasedIpV4TosFactory() {}

  /** @return the singleton instance of PropertiesBasedIpV4TosFactory */
  public static PropertiesBasedIpV4TosFactory getInstance() {
    return INSTANCE;
  }

  @Override
  @Deprecated
  public IpV4Tos newInstance(byte[] rawData, int offset, int length, NotApplicable number) {
    return newInstance(rawData, offset, length);
  }

  @Override
  public IpV4Tos newInstance(byte[] rawData, int offset, int length) {
    return newInstance(rawData, offset, length, getTargetClass());
  }

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @param tosClass tosClass
   * @return a new IpV4Tos object.
   * @throws IllegalStateException if an access to the newInstance method of the tosClass fails.
   * @throws IllegalArgumentException if an exception is thrown by newInstance method of the
   *     tosClass.
   * @throws NullPointerException if any of arguments are null.
   */
  public IpV4Tos newInstance(
      byte[] rawData, int offset, int length, Class<? extends IpV4Tos> tosClass) {
    ByteArrays.validateBounds(rawData, offset, length);
    if (tosClass == null) {
      throw new NullPointerException("tosClass is null.");
    }

    try {
      Method newInstance = tosClass.getMethod("newInstance", byte.class);
      return (IpV4Tos) newInstance.invoke(null, rawData[offset]);
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
  public Class<? extends IpV4Tos> getTargetClass(NotApplicable number) {
    return getTargetClass();
  }

  @Override
  public Class<? extends IpV4Tos> getTargetClass() {
    return PacketFactoryPropertiesLoader.getInstance().getIpV4TosClass();
  }
}
