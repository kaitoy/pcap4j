/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import java.io.ObjectStreamException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import org.pcap4j.packet.IpV4Packet.IpV4Tos;
import org.pcap4j.packet.namednumber.NotApplicable;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.14
 */
public final class PropertiesBasedIpV4TosFactory
implements PacketFactory<IpV4Tos, NotApplicable> {

  private static final PropertiesBasedIpV4TosFactory INSTANCE
    = new PropertiesBasedIpV4TosFactory();

  private PropertiesBasedIpV4TosFactory() {}

  /**
   *
   * @return the singleton instance of PropertiesBasedIpV4TosFactory
   */
  public static PropertiesBasedIpV4TosFactory getInstance() { return INSTANCE; }

  @Override
  public IpV4Tos newInstance(byte[] rawData, int offset, int length, NotApplicable... numbers) {
    ByteArrays.validateBounds(rawData, offset, length);
    Class<? extends IpV4Tos> tosClass
      = PacketFactoryPropertiesLoader.getInstance().getIpV4TosClass();
    if (tosClass == null) {
      throw new NullPointerException("tosClass is null.");
    }

    try {
      Method newInstance = tosClass.getMethod("newInstance", byte.class);
      return (IpV4Tos)newInstance.invoke(null, rawData[offset]);
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

  // Override deserializer to keep singleton
  @SuppressWarnings("static-method")
  private Object readResolve() throws ObjectStreamException {
    return INSTANCE;
  }

}
