/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory.propertiesbased;

import static org.pcap4j.util.ByteArrays.INT_SIZE_IN_BYTES;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import org.pcap4j.packet.IpV6Packet.IpV6FlowLabel;
import org.pcap4j.packet.factory.PacketFactory;
import org.pcap4j.packet.namednumber.NotApplicable;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.14
 */
public final class PropertiesBasedIpV6FlowLabelFactory
    implements PacketFactory<IpV6FlowLabel, NotApplicable> {

  private static final PropertiesBasedIpV6FlowLabelFactory INSTANCE =
      new PropertiesBasedIpV6FlowLabelFactory();

  private PropertiesBasedIpV6FlowLabelFactory() {}

  /** @return the singleton instance of PropertiesBasedIpV6FlowLabelFactory. */
  public static PropertiesBasedIpV6FlowLabelFactory getInstance() {
    return INSTANCE;
  }

  @Override
  @Deprecated
  public IpV6FlowLabel newInstance(byte[] rawData, int offset, int length, NotApplicable number) {
    return newInstance(rawData, offset, length);
  }

  @Override
  public IpV6FlowLabel newInstance(byte[] rawData, int offset, int length) {
    return newInstance(rawData, offset, length, getTargetClass());
  }

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @param clazz clazz
   * @return a new IpV6FlowLabel object.
   * @throws IllegalStateException if an access to the newInstance method of the clazz fails.
   * @throws IllegalArgumentException if an exception is thrown by newInstance method of the clazz.
   * @throws NullPointerException if any of arguments are null.
   */
  public IpV6FlowLabel newInstance(
      byte[] rawData, int offset, int length, Class<? extends IpV6FlowLabel> clazz) {
    ByteArrays.validateBounds(rawData, offset, length);
    if (clazz == null) {
      throw new NullPointerException("clazz is null.");
    }
    if (length < INT_SIZE_IN_BYTES) {
      throw new IllegalArgumentException("rawData is too short: " + length);
    }

    try {
      Method newInstance = clazz.getMethod("newInstance", int.class);
      return (IpV6FlowLabel) newInstance.invoke(null, ByteArrays.getInt(rawData, offset));
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

  @Override
  @Deprecated
  public Class<? extends IpV6FlowLabel> getTargetClass(NotApplicable number) {
    return getTargetClass();
  }

  @Override
  public Class<? extends IpV6FlowLabel> getTargetClass() {
    return PacketFactoryPropertiesLoader.getInstance().getIpV6FlowLabelClass();
  }
}
