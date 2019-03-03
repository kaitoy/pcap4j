/** *****************************************************************************
 *  Copyright (C) 2019 Thales AVS, All Rights Reserved.
 ** ****************************************************************************/

package org.pcap4j.packet.factory.propertiesbased.services;

import org.pcap4j.packet.factory.PacketFactoryBinder;

public class PacketFactoryBinderProvider implements org.pcap4j.packet.factory.PacketFactoryBinderProvider {
    
    private static final PacketFactoryBinder INSTANCE = new org.pcap4j.packet.factory.propertiesbased.services.PacketFactoryBinder();

    /** {@inheritDoc} */
    @Override
    public PacketFactoryBinder getInstance() {
        return INSTANCE;
    }

}
