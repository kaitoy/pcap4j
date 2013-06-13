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
 * @since pcap4j 0.9.6
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
   * @param numberClass
   * @return PacketFactory
   */
  public static PacketFactory<NamedNumber<?>> getFactory(
    Class<? extends NamedNumber<?>> numberClass
  ) {
    if (numberClass == null) {
      throw new NullPointerException("numberClass: " + numberClass);
    }

    if (FACTORY_BINDER != null) {
      return FACTORY_BINDER.getFactory(numberClass);
    }
    else {
      return SimpleFactoryBinder.getInstance().getFactory(numberClass);
    }
  }

}
