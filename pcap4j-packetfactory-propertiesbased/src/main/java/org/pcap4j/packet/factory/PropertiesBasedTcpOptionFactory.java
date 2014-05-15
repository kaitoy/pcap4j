/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IllegalTcpOption;
import org.pcap4j.packet.TcpPacket.TcpOption;
import org.pcap4j.packet.namednumber.TcpOptionKind;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.14
 */
public final class
PropertiesBasedTcpOptionFactory
implements PacketFactory<TcpOption, TcpOptionKind> {

  private static final PropertiesBasedTcpOptionFactory INSTANCE
    = new PropertiesBasedTcpOptionFactory();

  private PropertiesBasedTcpOptionFactory() {}

  /**
   *
   * @return the singleton instance of PropertiesBasedTcpOptionFactory.
   */
  public static PropertiesBasedTcpOptionFactory getInstance() { return INSTANCE; }

  @Override
  public TcpOption newInstance(byte[] rawData, TcpOptionKind number) {
    return newInstance(rawData, getTargetClass(number));
  }

  @Override
  public TcpOption newInstance(byte[] rawData) {
    return newInstance(rawData, getTargetClass());
  }

  /**
   *
   * @param rawData
   * @param dataClass
   * @return a new TcpOption object.
   */
  public TcpOption newInstance(byte[] rawData, Class<? extends TcpOption> dataClass) {
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
      return (TcpOption)newInstance.invoke(null, rawData);
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
        return IllegalTcpOption.newInstance(rawData);
      }
      throw new IllegalStateException(e.getTargetException());
    }
  }

  @Override
  public Class<? extends TcpOption> getTargetClass(TcpOptionKind number) {
    if (number == null) {
      throw new NullPointerException(" number: " + number);
    }
    return PacketFactoryPropertiesLoader.getInstance().getTcpOptionClass(number);
  }

  @Override
  public Class<? extends TcpOption> getTargetClass() {
    return PacketFactoryPropertiesLoader.getInstance().getUnknownTcpOptionClass();
  }

}
