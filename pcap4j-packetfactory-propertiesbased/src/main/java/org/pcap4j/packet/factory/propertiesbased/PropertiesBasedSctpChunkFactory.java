/*_##########################################################################
  _##
  _##  Copyright (C) 2016-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory.propertiesbased;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IllegalSctpChunk;
import org.pcap4j.packet.SctpPacket.SctpChunk;
import org.pcap4j.packet.factory.PacketFactory;
import org.pcap4j.packet.namednumber.SctpChunkType;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.6.6
 */
public final class PropertiesBasedSctpChunkFactory
    implements PacketFactory<SctpChunk, SctpChunkType> {

  private static final PropertiesBasedSctpChunkFactory INSTANCE =
      new PropertiesBasedSctpChunkFactory();

  private PropertiesBasedSctpChunkFactory() {}

  /** @return the singleton instance of PropertiesBasedSctpChunkFactory. */
  public static PropertiesBasedSctpChunkFactory getInstance() {
    return INSTANCE;
  }

  @Override
  public SctpChunk newInstance(byte[] rawData, int offset, int length, SctpChunkType number) {
    return newInstance(rawData, offset, length, getTargetClass(number));
  }

  @Override
  public SctpChunk newInstance(byte[] rawData, int offset, int length) {
    return newInstance(rawData, offset, length, getTargetClass());
  }

  /**
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @param dataClass dataClass
   * @return a new SctpChunk object.
   * @throws IllegalStateException if an access to the newInstance method of the dataClass fails.
   * @throws IllegalArgumentException if an exception other than {@link IllegalRawDataException} is
   *     thrown by newInstance method of the dataClass.
   * @throws NullPointerException if any of arguments are null.
   */
  public SctpChunk newInstance(
      byte[] rawData, int offset, int length, Class<? extends SctpChunk> dataClass) {
    if (rawData == null || dataClass == null) {
      StringBuilder sb = new StringBuilder(50);
      sb.append("rawData: ").append(rawData).append(" dataClass: ").append(dataClass);
      throw new NullPointerException(sb.toString());
    }

    try {
      Method newInstance = dataClass.getMethod("newInstance", byte[].class, int.class, int.class);
      return (SctpChunk) newInstance.invoke(null, rawData, offset, length);
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
        return IllegalSctpChunk.newInstance(rawData, offset, length);
      }
      throw new IllegalArgumentException(e);
    }
  }

  @Override
  public Class<? extends SctpChunk> getTargetClass(SctpChunkType number) {
    if (number == null) {
      throw new NullPointerException("number is null.");
    }
    return PacketFactoryPropertiesLoader.getInstance().getSctpChunkClass(number);
  }

  @Override
  public Class<? extends SctpChunk> getTargetClass() {
    return PacketFactoryPropertiesLoader.getInstance().getUnknownSctpChunkClass();
  }
}
