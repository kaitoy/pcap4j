/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import org.pcap4j.packet.IllegalIpV4Option;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV4Packet.IpV4Option;
import org.pcap4j.packet.namednumber.IpV4OptionType;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.14
 */
public final class
PropertiesBasedIpV4OptionFactory
implements PacketFactory<IpV4Option, IpV4OptionType> {

  private static final PropertiesBasedIpV4OptionFactory INSTANCE
    = new PropertiesBasedIpV4OptionFactory();

  private PropertiesBasedIpV4OptionFactory() {}

  /**
   *
   * @return the singleton instance of PropertiesBasedIpV4OptionFactory.
   */
  public static PropertiesBasedIpV4OptionFactory getInstance() { return INSTANCE; }

  @Override
  public IpV4Option newInstance(byte[] rawData, IpV4OptionType number) {
    return newInstance(rawData, getTargetClass(number));
  }

  @Override
  public IpV4Option newInstance(byte[] rawData) {
    return newInstance(rawData, getTargetClass());
  }

  /**
   *
   * @param rawData
   * @param dataClass
   * @return a new IpV4Option object.
   */
  public IpV4Option newInstance(byte[] rawData, Class<? extends IpV4Option> dataClass) {
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
      return (IpV4Option)newInstance.invoke(null, rawData);
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
        return IllegalIpV4Option.newInstance(rawData);
      }
      throw new IllegalStateException(e.getTargetException());
    }
  }

  @Override
  public Class<? extends IpV4Option> getTargetClass(IpV4OptionType number) {
    if (number == null) {
      throw new NullPointerException("number: " + number);
    }
    return PacketFactoryPropertiesLoader.getInstance().getIpV4OptionClass(number);
  }

  @Override
  public Class<? extends IpV4Option> getTargetClass() {
    return PacketFactoryPropertiesLoader.getInstance().getUnknownIpV4OptionClass();
  }

}
