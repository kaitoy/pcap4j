/*
 * ***************************************************************************
 * Copyright (C) 2019 Thales AVS, All Rights Reserved. *
 * ***************************************************************************
 */
package org.pcap4j.packet.factory.statik.services;

import org.pcap4j.packet.factory.PacketFactoryBinder;
import org.pcap4j.packet.factory.PacketFactoryBinderProvider;

/**
 * @author Jordan Dubie
 * @since pcap4j 1.8.0
 */
public class StaticPacketFactoryBinderProvider implements PacketFactoryBinderProvider {

  @Override
  public PacketFactoryBinder getBinder() {
    return StaticPacketFactoryBinder.getInstance();
  }
}
