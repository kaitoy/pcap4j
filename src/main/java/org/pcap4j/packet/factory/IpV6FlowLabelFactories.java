/*_##########################################################################
  _##
  _##  Copyright (C) 2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import org.pcap4j.packet.PacketPropertiesLoader;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class IpV6FlowLabelFactories {

  private IpV6FlowLabelFactories() { throw new AssertionError(); }

  /**
   *
   * @param numberClass
   * @return
   */
  public static IpV6FlowLabelFactory getFactory() {
    Class<? extends IpV6FlowLabelFactory> factoryClass
      = (Class<? extends IpV6FlowLabelFactory>)PacketPropertiesLoader
          .getInstance().getIpV6FlowLabelFactoryClass();
    try {
      Method getInstance = factoryClass.getMethod("getInstance");
      return (IpV6FlowLabelFactory)getInstance.invoke(null);
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
