/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import org.pcap4j.packet.namednumber.NamedNumber;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Iterator;
import java.util.ServiceConfigurationError;
import java.util.ServiceLoader;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class PacketFactories {

  private static final Logger logger = LoggerFactory.getLogger(PacketFactories.class);
  private static final PacketFactoryBinder FACTORY_BINDER;

  static {
    PacketFactoryBinder factoryBinder = null;
    try {
      ServiceLoader<PacketFactoryBinderProvider> loader =
          ServiceLoader.load(PacketFactoryBinderProvider.class);
      Iterator<PacketFactoryBinderProvider> iter = loader.iterator();
      if (iter.hasNext()) {
        PacketFactoryBinderProvider packetFactoryBinderProvider = iter.next();
        factoryBinder = packetFactoryBinderProvider.getBinder();
        logger.info("Succeeded in PacketFactoryBinderProvider.getBinder()");
      }
    } catch (ServiceConfigurationError e) {
      logger.warn(e.getClass().getName() + ": " + e.getMessage());
    }
    FACTORY_BINDER = factoryBinder;
  }

  private PacketFactories() {
    throw new AssertionError();
  }

  /**
   * @param <T> target
   * @param <N> number
   * @param targetClass targetClass
   * @param numberClass numberClass
   * @return a {@link org.pcap4j.packet.factory.PacketFactory PacketFactory} object.
   */
  public static <T, N extends NamedNumber<?, ?>> PacketFactory<T, N> getFactory(
      Class<T> targetClass, Class<N> numberClass) {
    if (numberClass == null || targetClass == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("numberClass: ").append(numberClass).append(" targetClass: ").append(targetClass);
      throw new NullPointerException(sb.toString());
    }

    if (FACTORY_BINDER != null) {
      return FACTORY_BINDER.getPacketFactory(targetClass, numberClass);
    } else {
      return SimplePacketFactoryBinder.getInstance().getPacketFactory(targetClass, numberClass);
    }
  }
}
