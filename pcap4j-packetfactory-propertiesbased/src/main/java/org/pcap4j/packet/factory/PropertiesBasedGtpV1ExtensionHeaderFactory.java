/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import org.pcap4j.packet.GtpV1Packet.GtpV1ExtensionHeader;
import org.pcap4j.packet.IllegalGtpV1ExtensionHeader;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.namednumber.GtpV1ExtensionHeaderType;

/**
 * @author Leo Ma
 * @since pcap4j 1.7.7
 */
public final class PropertiesBasedGtpV1ExtensionHeaderFactory
    implements PacketFactory<GtpV1ExtensionHeader, GtpV1ExtensionHeaderType> {

  private static final PropertiesBasedGtpV1ExtensionHeaderFactory INSTANCE =
      new PropertiesBasedGtpV1ExtensionHeaderFactory();

  private PropertiesBasedGtpV1ExtensionHeaderFactory() {}

  /** @return the singleton instance of PropertiesBasedGtpV1ExtensionHeaderFactory. */
  public static PropertiesBasedGtpV1ExtensionHeaderFactory getInstance() {
    return INSTANCE;
  }

  @Override
  public GtpV1ExtensionHeader newInstance(
      byte[] rawData, int offset, int length, GtpV1ExtensionHeaderType number) {
    return newInstance(rawData, offset, length, getTargetClass(number));
  }

  @Override
  public GtpV1ExtensionHeader newInstance(byte[] rawData, int offset, int length) {
    return newInstance(rawData, offset, length, getTargetClass());
  }

  /**
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @param dataClass dataClass
   * @return a new GtpV1ExtensionHeader object.
   * @throws IllegalStateException if an access to the newInstance method of the dataClass fails.
   * @throws IllegalArgumentException if an exception other than {@link IllegalRawDataException} is
   *     thrown by newInstance method of the dataClass.
   * @throws NullPointerException if any of arguments are null.
   */
  public GtpV1ExtensionHeader newInstance(
      byte[] rawData, int offset, int length, Class<? extends GtpV1ExtensionHeader> dataClass) {
    if (rawData == null || dataClass == null) {
      StringBuilder sb = new StringBuilder(50);
      sb.append("rawData: ").append(rawData).append(" dataClass: ").append(dataClass);
      throw new NullPointerException(sb.toString());
    }

    try {
      Method newInstance = dataClass.getMethod("newInstance", byte[].class, int.class, int.class);
      return (GtpV1ExtensionHeader) newInstance.invoke(null, rawData, offset, length);
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
        return IllegalGtpV1ExtensionHeader.newInstance(rawData, offset, length);
      }
      throw new IllegalArgumentException(e);
    }
  }

  @Override
  public Class<? extends GtpV1ExtensionHeader> getTargetClass(GtpV1ExtensionHeaderType number) {
    if (number == null) {
      throw new NullPointerException("number must not be null");
    }
    return PacketFactoryPropertiesLoader.getInstance().getGtpV1ExtensionHeaderClass(number);
  }

  @Override
  public Class<? extends GtpV1ExtensionHeader> getTargetClass() {
    return PacketFactoryPropertiesLoader.getInstance().getUnKnownGtpV1ExtensionHeaderClass();
  }
}
