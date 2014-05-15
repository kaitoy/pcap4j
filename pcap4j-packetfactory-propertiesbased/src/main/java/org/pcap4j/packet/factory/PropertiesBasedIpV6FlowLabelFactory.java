/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import static org.pcap4j.util.ByteArrays.*;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import org.pcap4j.packet.IpV6Packet.IpV6FlowLabel;
import org.pcap4j.packet.namednumber.NA;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.14
 */
public final class PropertiesBasedIpV6FlowLabelFactory
implements PacketFactory<IpV6FlowLabel, NA> {

  private static final PropertiesBasedIpV6FlowLabelFactory INSTANCE
    = new PropertiesBasedIpV6FlowLabelFactory();

  private PropertiesBasedIpV6FlowLabelFactory() {}

  /**
   *
   * @return the singleton instance of PropertiesBasedIpV6FlowLabelFactory.
   */
  public static PropertiesBasedIpV6FlowLabelFactory getInstance() { return INSTANCE; }

  @Override
  @Deprecated
  public IpV6FlowLabel newInstance(byte[] rawData, NA number) {
    return newInstance(rawData);
  }

  @Override
  public IpV6FlowLabel newInstance(byte[] rawData) {
    return newInstance(rawData, getTargetClass());
  }

  /**
   *
   * @param rawData
   * @param clazz
   * @return a new IpV6FlowLabel object.
   */
  public IpV6FlowLabel newInstance(
    byte[] rawData, Class<? extends IpV6FlowLabel> clazz
  ) {
    if (rawData == null || clazz == null) {
      StringBuilder sb = new StringBuilder(50);
      sb.append("rawData: ")
        .append(rawData)
        .append(" clazz: ")
        .append(clazz);
      throw new NullPointerException(sb.toString());
    }
    if (rawData.length < INT_SIZE_IN_BYTES) {
      throw new IllegalArgumentException(
              "rawData is too short: " + ByteArrays.toHexString(rawData, " ")
            );
    }

    try {
      Method newInstance = clazz.getMethod("newInstance", int.class);
      return (IpV6FlowLabel)newInstance.invoke(null, ByteArrays.getInt(rawData, 0));
    } catch (SecurityException e) {
      throw new IllegalStateException(e);
    } catch (NoSuchMethodException e) {
      throw new IllegalStateException(e);
    } catch (IllegalArgumentException e) {
      throw new IllegalStateException(e);
    } catch (IllegalAccessException e) {
      throw new IllegalStateException(e);
    } catch (InvocationTargetException e) {
      throw new IllegalStateException(e.getTargetException());
    }
  }

  @Override
  @Deprecated
  public Class<? extends IpV6FlowLabel> getTargetClass(NA number) {
    return getTargetClass();
  }

  @Override
  public Class<? extends IpV6FlowLabel> getTargetClass() {
    return PacketFactoryPropertiesLoader.getInstance().getIpV6FlowLabelClass();
  }

}
