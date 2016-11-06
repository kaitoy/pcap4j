/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import static org.pcap4j.util.ByteArrays.*;

import java.io.ObjectStreamException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import org.pcap4j.packet.IpV6Packet.IpV6FlowLabel;
import org.pcap4j.packet.namednumber.NotApplicable;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.14
 */
public final class PropertiesBasedIpV6FlowLabelFactory
implements PacketFactory<IpV6FlowLabel, NotApplicable> {

  private static final PropertiesBasedIpV6FlowLabelFactory INSTANCE
    = new PropertiesBasedIpV6FlowLabelFactory();

  private PropertiesBasedIpV6FlowLabelFactory() {}

  /**
   *
   * @return the singleton instance of PropertiesBasedIpV6FlowLabelFactory.
   */
  public static PropertiesBasedIpV6FlowLabelFactory getInstance() { return INSTANCE; }

  @Override
  public IpV6FlowLabel newInstance(
    byte[] rawData, int offset, int length, NotApplicable... number
  ) {
    ByteArrays.validateBounds(rawData, offset, length);
    Class<? extends IpV6FlowLabel> clazz
      = PacketFactoryPropertiesLoader.getInstance().getIpV6FlowLabelClass();
    if (clazz == null) {
      throw new NullPointerException("clazz is null.");
    }
    if (length < INT_SIZE_IN_BYTES) {
      throw new IllegalArgumentException("rawData is too short: " + length);
    }

    try {
      Method newInstance = clazz.getMethod("newInstance", int.class);
      return (IpV6FlowLabel)newInstance.invoke(null, ByteArrays.getInt(rawData, offset));
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

  // Override deserializer to keep singleton
  @SuppressWarnings("static-method")
  private Object readResolve() throws ObjectStreamException {
    return INSTANCE;
  }

}
