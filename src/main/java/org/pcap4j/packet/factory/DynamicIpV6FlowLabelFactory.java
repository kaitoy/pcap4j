/*_##########################################################################
  _##
  _##  Copyright (C) 2012 Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import org.pcap4j.packet.IpV6Packet.IpV6FlowLabel;
import org.pcap4j.packet.PacketPropertiesLoader;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class DynamicIpV6FlowLabelFactory implements IpV6FlowLabelFactory {

  private static final DynamicIpV6FlowLabelFactory INSTANCE
    = new DynamicIpV6FlowLabelFactory();

  private DynamicIpV6FlowLabelFactory() {}

  /**
   *
   * @return
   */
  public static DynamicIpV6FlowLabelFactory getInstance() { return INSTANCE; }

  public IpV6FlowLabel newFlowLabel(int value) {
    Class<? extends IpV6FlowLabel> clazz
      = PacketPropertiesLoader.getInstance().getIpV6FlowLabelClass();
    return newFlowLabel(value, clazz);
  }

  /**
   *
   * @param value
   * @param clazz
   * @return
   */
  public IpV6FlowLabel newFlowLabel(
    int value, Class<? extends IpV6FlowLabel> clazz
  ) {
    if (clazz == null) {
      throw new NullPointerException("clazz may not be null");
    }

    try {
      Method newInstance = clazz.getMethod("newInstance", int.class);
      return (IpV6FlowLabel)newInstance.invoke(null, value);
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

}
