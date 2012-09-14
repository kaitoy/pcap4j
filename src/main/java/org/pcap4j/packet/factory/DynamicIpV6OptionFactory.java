/*_##########################################################################
  _##
  _##  Copyright (C) 2012 Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import org.pcap4j.packet.IllegalIpV6Option;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV6ExtOptionsPacket.IpV6Option;
import org.pcap4j.packet.PacketPropertiesLoader;
import org.pcap4j.packet.namednumber.IpV6OptionType;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class
DynamicIpV6OptionFactory
implements ClassifiedDataFactory<IpV6Option, IpV6OptionType> {

  private static final DynamicIpV6OptionFactory INSTANCE
    = new DynamicIpV6OptionFactory();

  private DynamicIpV6OptionFactory() {}

  /**
   *
   * @return
   */
  public static DynamicIpV6OptionFactory getInstance() { return INSTANCE; }

  public IpV6Option newData(byte[] rawData, IpV6OptionType number) {
    if (number == null) {
      throw new NullPointerException(" number: " + number);
    }

    Class<? extends IpV6Option> dataClass
      = PacketPropertiesLoader.getInstance().getIpV6OptionClass(number);
    return newData(rawData, dataClass);
  }

  public IpV6Option newData(byte[] rawData) {
    Class<? extends IpV6Option> dataClass
      = PacketPropertiesLoader.getInstance().getUnknownIpV6OptionClass();
    return newData(rawData, dataClass);
  }

  /**
   *
   * @param rawData
   * @param dataClass
   * @return
   */
  public IpV6Option newData(byte[] rawData, Class<? extends IpV6Option> dataClass) {
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
      return (IpV6Option)newInstance.invoke(null, rawData);
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
        return IllegalIpV6Option.newInstance(rawData);
      }
      throw new IllegalStateException(e.getTargetException());
    }
  }

}
