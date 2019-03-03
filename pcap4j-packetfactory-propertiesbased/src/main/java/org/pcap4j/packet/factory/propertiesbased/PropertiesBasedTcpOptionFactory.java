/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory.propertiesbased;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IllegalTcpOption;
import org.pcap4j.packet.TcpPacket.TcpOption;
import org.pcap4j.packet.factory.PacketFactory;
import org.pcap4j.packet.namednumber.TcpOptionKind;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.14
 */
public final class PropertiesBasedTcpOptionFactory
    implements PacketFactory<TcpOption, TcpOptionKind> {

  private static final PropertiesBasedTcpOptionFactory INSTANCE =
      new PropertiesBasedTcpOptionFactory();

  private PropertiesBasedTcpOptionFactory() {}

  /** @return the singleton instance of PropertiesBasedTcpOptionFactory. */
  public static PropertiesBasedTcpOptionFactory getInstance() {
    return INSTANCE;
  }

  @Override
  public TcpOption newInstance(byte[] rawData, int offset, int length, TcpOptionKind number) {
    return newInstance(rawData, offset, length, getTargetClass(number));
  }

  @Override
  public TcpOption newInstance(byte[] rawData, int offset, int length) {
    return newInstance(rawData, offset, length, getTargetClass());
  }

  /**
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @param dataClass dataClass
   * @return a new TcpOption object.
   * @throws IllegalStateException if an access to the newInstance method of the dataClass fails.
   * @throws IllegalArgumentException if an exception other than {@link IllegalRawDataException} is
   *     thrown by newInstance method of the dataClass.
   * @throws NullPointerException if any of arguments are null.
   */
  public TcpOption newInstance(
      byte[] rawData, int offset, int length, Class<? extends TcpOption> dataClass) {
    if (rawData == null || dataClass == null) {
      StringBuilder sb = new StringBuilder(40);
      sb.append("rawData: ").append(rawData).append(" dataClass: ").append(dataClass);
      throw new NullPointerException(sb.toString());
    }

    try {
      Method newInstance = dataClass.getMethod("newInstance", byte[].class, int.class, int.class);
      return (TcpOption) newInstance.invoke(null, rawData, offset, length);
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
        return IllegalTcpOption.newInstance(rawData, offset, length);
      }
      throw new IllegalArgumentException(e);
    }
  }

  @Override
  public Class<? extends TcpOption> getTargetClass(TcpOptionKind number) {
    if (number == null) {
      throw new NullPointerException(" number is null.");
    }
    return PacketFactoryPropertiesLoader.getInstance().getTcpOptionClass(number);
  }

  @Override
  public Class<? extends TcpOption> getTargetClass() {
    return PacketFactoryPropertiesLoader.getInstance().getUnknownTcpOptionClass();
  }
}
