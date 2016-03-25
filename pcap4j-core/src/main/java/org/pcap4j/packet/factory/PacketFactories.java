/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import org.pcap4j.packet.namednumber.NamedNumber;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ServiceLoader;

/**
 * @author anylain
 * @since pcap4j 1.6.3
 */
public final class PacketFactories {

    private static final Logger logger
            = LoggerFactory.getLogger(PacketFactories.class);
    private static PacketFactoryBinder factoryBinder;

    private static Object factoryBinderInitLock = new Object();

    private static PacketFactoryBinder getPacketFactoryBinder() {
        if (factoryBinder == null) {
            synchronized (factoryBinderInitLock) {
                if (factoryBinder == null) {
                    ServiceLoader<PacketFactoryBinder> loader = ServiceLoader.load(PacketFactoryBinder.class);
                    if (loader.iterator().hasNext()) {
                        factoryBinder = loader.iterator().next();
                        logger.info("PacketFactoryBinder plugin '{}' load succeed.",
                                factoryBinder.getClass().getSimpleName());
                    } else {
                        factoryBinder = SimplePacketFactoryBinder.getInstance();
                        logger.info("Can't found any PacketFactoryBinder plugin, will use 'SimplePacketFactoryBinder'.");
                    }
                }
            }
        }
        return factoryBinder;
    }

    private PacketFactories() {
        throw new AssertionError();
    }

    /**
     * @param <T>         target
     * @param <N>         number
     * @param targetClass targetClass
     * @param numberClass numberClass
     * @return a {@link org.pcap4j.packet.factory.PacketFactory PacketFactory} object.
     */
    public static <T, N extends NamedNumber<?, ?>> PacketFactory<T, N> getFactory(
            Class<T> targetClass, Class<N> numberClass
    ) {
        if (numberClass == null || targetClass == null) {
            StringBuilder sb = new StringBuilder();
            sb.append("numberClass: ").append(numberClass)
                    .append(" targetClass: ").append(targetClass);
            throw new NullPointerException(sb.toString());
        }

        return getPacketFactoryBinder().getPacketFactory(targetClass, numberClass);
    }

}
