/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory.propertiesbased;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import org.pcap4j.packet.IllegalIpV6Option;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV6ExtOptionsPacket.IpV6Option;
import org.pcap4j.packet.factory.PacketFactory;
import org.pcap4j.packet.namednumber.IpV6OptionType;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.14
 */
public final class PropertiesBasedIpV6OptionFactory
    implements PacketFactory<IpV6Option, IpV6OptionType> {

  private static final PropertiesBasedIpV6OptionFactory INSTANCE =
      new PropertiesBasedIpV6OptionFactory();

  private PropertiesBasedIpV6OptionFactory() {}

  /** @return the singleton instance of PropertiesBasedIpV6OptionFactory. */
  public static PropertiesBasedIpV6OptionFactory getInstance() {
    return INSTANCE;
  }

  @Override
  public IpV6Option newInstance(byte[] rawData, int offset, int length, IpV6OptionType number) {
    return newInstance(rawData, offset, length, getTargetClass(number));
  }

  @Override
  public IpV6Option newInstance(byte[] rawData, int offset, int length) {
    return newInstance(rawData, offset, length, getTargetClass());
  }

  /**
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @param dataClass dataClass
   * @return a new IpV6Option object.
   * @throws IllegalStateException if an access to the newInstance method of the dataClass fails.
   * @throws IllegalArgumentException if an exception other than {@link IllegalRawDataException} is
   *     thrown by newInstance method of the dataClass.
   * @throws NullPointerException if any of arguments are null.
   */
  public IpV6Option newInstance(
      byte[] rawData, int offset, int length, Class<? extends IpV6Option> dataClass) {
    if (rawData == null || dataClass == null) {
      StringBuilder sb = new StringBuilder(50);
      sb.append("rawData: ").append(rawData).append(" dataClass: ").append(dataClass);
      throw new NullPointerException(sb.toString());
    }

    try {
      Method newInstance = dataClass.getMethod("newInstance", byte[].class, int.class, int.class);
      return (IpV6Option) newInstance.invoke(null, rawData, offset, length);
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
        return IllegalIpV6Option.newInstance(rawData, offset, length);
      }
      throw new IllegalArgumentException(e);
    }
  }

  @Override
  public Class<? extends IpV6Option> getTargetClass(IpV6OptionType number) {
    if (number == null) {
      throw new NullPointerException(" number: " + number);
    }
    return PacketFactoryPropertiesLoader.getInstance().getIpV6OptionClass(number);
  }

  @Override
  public Class<? extends IpV6Option> getTargetClass() {
    return PacketFactoryPropertiesLoader.getInstance().getUnknownIpV6OptionClass();
  }
}
