/*_##########################################################################
  _##
  _##  Copyright (C) 2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import org.pcap4j.packet.namednumber.NamedNumber;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class PacketFactories {

  private static final Logger logger
    = LoggerFactory.getLogger(PacketFactories.class);
  private static final FactoryBinder FACTORY_BINDER;

  static {
    FactoryBinder factoryBinder = null;
    try {
      factoryBinder = FactoryBinder.getInstance();
      logger.info("Succeeded in FactoryBinder.getInstance()");
    } catch (NoClassDefFoundError e) {
      logger.warn(e.getMessage());
    } catch (NoSuchMethodError e) {
      logger.warn(e.getMessage());
    }
    FACTORY_BINDER = factoryBinder;
  }

  private PacketFactories() { throw new AssertionError(); }

  /**
   *
   * @param targetClass
   * @param numberClass
   * @return a {@link org.pcap4j.packet.factory.PacketFactory PacketFactory} object.
   */
  public static <T, N extends NamedNumber<?>> PacketFactory<T, N> getFactory(
    Class<T> targetClass, Class<N> numberClass
  ) {
    if (numberClass == null || targetClass == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("numberClass: ").append(numberClass)
        .append(" targetClass: ").append(targetClass);
      throw new NullPointerException(sb.toString());
    }

    if (FACTORY_BINDER != null) {
      return FACTORY_BINDER.getFactory(targetClass, numberClass);
    }
    else {
      return SimpleFactoryBinder.getInstance().getFactory(targetClass, numberClass);
    }

  }

}
