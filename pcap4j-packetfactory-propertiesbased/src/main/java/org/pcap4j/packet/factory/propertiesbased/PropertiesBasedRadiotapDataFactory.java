/*_##########################################################################
  _##
  _##  Copyright (C) 2016-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory.propertiesbased;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import org.pcap4j.packet.IllegalRadiotapData;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.RadiotapPacket.RadiotapData;
import org.pcap4j.packet.factory.PacketFactory;
import org.pcap4j.packet.namednumber.RadiotapPresentBitNumber;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.6.5
 */
public final class PropertiesBasedRadiotapDataFactory
    implements PacketFactory<RadiotapData, RadiotapPresentBitNumber> {

  private static final PropertiesBasedRadiotapDataFactory INSTANCE =
      new PropertiesBasedRadiotapDataFactory();

  private PropertiesBasedRadiotapDataFactory() {}

  /** @return the singleton instance of PropertiesBasedRadiotapDataFactory. */
  public static PropertiesBasedRadiotapDataFactory getInstance() {
    return INSTANCE;
  }

  @Override
  public RadiotapData newInstance(
      byte[] rawData, int offset, int length, RadiotapPresentBitNumber num) {
    return newInstance(rawData, offset, length, getTargetClass(num));
  }

  @Override
  public RadiotapData newInstance(byte[] rawData, int offset, int length) {
    return newInstance(rawData, offset, length, getTargetClass());
  }

  /**
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @param dataClass dataClass
   * @return a new RadiotapDataField object.
   * @throws IllegalStateException if an access to the newInstance method of the dataClass fails.
   * @throws IllegalArgumentException if an exception other than {@link IllegalRawDataException} is
   *     thrown by newInstance method of the dataClass.
   * @throws NullPointerException if any of arguments are null.
   */
  public RadiotapData newInstance(
      byte[] rawData, int offset, int length, Class<? extends RadiotapData> dataClass) {
    if (rawData == null || dataClass == null) {
      StringBuilder sb = new StringBuilder(50);
      sb.append("rawData: ").append(rawData).append(" dataClass: ").append(dataClass);
      throw new NullPointerException(sb.toString());
    }

    try {
      Method newInstance = dataClass.getMethod("newInstance", byte[].class, int.class, int.class);
      return (RadiotapData) newInstance.invoke(null, rawData, offset, length);
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
        return IllegalRadiotapData.newInstance(rawData, offset, length);
      }
      throw new IllegalArgumentException(e);
    }
  }

  @Override
  public Class<? extends RadiotapData> getTargetClass(RadiotapPresentBitNumber num) {
    if (num == null) {
      throw new NullPointerException("num must not be null");
    }
    return PacketFactoryPropertiesLoader.getInstance().getRadiotapDataFieldClass(num);
  }

  @Override
  public Class<? extends RadiotapData> getTargetClass() {
    return PacketFactoryPropertiesLoader.getInstance().getUnknownRadiotapDataFieldClass();
  }
}
