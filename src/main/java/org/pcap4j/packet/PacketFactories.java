/*_##########################################################################
  _##
  _##  Copyright (C) 2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import org.pcap4j.packet.namednumber.NamedNumber;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.6
 */
public final class PacketFactories {

  private PacketFactories() { throw new AssertionError(); }

  /**
   *
   * @param numberClass
   * @return
   */
  public static PacketFactory getPacketFactory(
    Class<? extends NamedNumber<?>> numberClass
  ) {
    if (numberClass == null) {
      throw new NullPointerException("numberClass: " + numberClass);
    }

    Class<? extends PacketFactory> factoryClass
      = PacketPropertiesLoader.getInstance().getPacketFactoryImplClass(numberClass);

    try {
      Method getInstance = factoryClass.getMethod("getInstance");
      return (PacketFactory)getInstance.invoke(null);
    } catch (SecurityException e) {
      throw new IllegalStateException(e);
    } catch (NoSuchMethodException e) {
      throw new IllegalStateException(e);
    } catch (IllegalArgumentException e) {
      throw new IllegalStateException(e);
    } catch (IllegalAccessException e) {
      throw new IllegalStateException(e);
    } catch (InvocationTargetException e) {
      throw new IllegalStateException(e);
    }
  }

}
