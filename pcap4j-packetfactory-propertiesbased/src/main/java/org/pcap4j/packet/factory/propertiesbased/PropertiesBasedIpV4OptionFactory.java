/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory.propertiesbased;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import org.pcap4j.packet.IllegalIpV4Option;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV4Packet.IpV4Option;
import org.pcap4j.packet.factory.PacketFactory;
import org.pcap4j.packet.namednumber.IpV4OptionType;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.14
 */
public final class PropertiesBasedIpV4OptionFactory
    implements PacketFactory<IpV4Option, IpV4OptionType> {

  private static final PropertiesBasedIpV4OptionFactory INSTANCE =
      new PropertiesBasedIpV4OptionFactory();

  private PropertiesBasedIpV4OptionFactory() {}

  /** @return the singleton instance of PropertiesBasedIpV4OptionFactory. */
  public static PropertiesBasedIpV4OptionFactory getInstance() {
    return INSTANCE;
  }

  @Override
  public IpV4Option newInstance(byte[] rawData, int offset, int length, IpV4OptionType number) {
    return newInstance(rawData, offset, length, getTargetClass(number));
  }

  @Override
  public IpV4Option newInstance(byte[] rawData, int offset, int length) {
    return newInstance(rawData, offset, length, getTargetClass());
  }

  /**
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @param dataClass dataClass
   * @return a new IpV4Option object.
   * @throws IllegalStateException if an access to the newInstance method of the dataClass fails.
   * @throws IllegalArgumentException if an exception other than {@link IllegalRawDataException} is
   *     thrown by newInstance method of the dataClass.
   * @throws NullPointerException if any of arguments are null.
   */
  public IpV4Option newInstance(
      byte[] rawData, int offset, int length, Class<? extends IpV4Option> dataClass) {
    if (rawData == null || dataClass == null) {
      StringBuilder sb = new StringBuilder(50);
      sb.append("rawData: ").append(rawData).append(" dataClass: ").append(dataClass);
      throw new NullPointerException(sb.toString());
    }

    try {
      Method newInstance = dataClass.getMethod("newInstance", byte[].class, int.class, int.class);
      return (IpV4Option) newInstance.invoke(null, rawData, offset, length);
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
        return IllegalIpV4Option.newInstance(rawData, offset, length);
      }
      throw new IllegalArgumentException(e);
    }
  }

  @Override
  public Class<? extends IpV4Option> getTargetClass(IpV4OptionType number) {
    if (number == null) {
      throw new NullPointerException("number is null.");
    }
    return PacketFactoryPropertiesLoader.getInstance().getIpV4OptionClass(number);
  }

  @Override
  public Class<? extends IpV4Option> getTargetClass() {
    return PacketFactoryPropertiesLoader.getInstance().getUnknownIpV4OptionClass();
  }
}
