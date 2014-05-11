/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2014  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import java.util.HashMap;
import java.util.Map;
import org.pcap4j.packet.IllegalPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.NamedNumber;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.16
 */
public abstract class AbstractStaticPacketFactory<N extends NamedNumber<?>>
implements PacketFactory<Packet, N> {

  protected final Map<N, PacketInstantiater> instantiaters
    = new HashMap<N, PacketInstantiater>();

  public Packet newInstance(byte[] rawData, N number) {
    if (rawData == null || number == null) {
      StringBuilder sb = new StringBuilder(40);
      sb.append("rawData: ")
        .append(rawData)
        .append(" number: ")
        .append(number);
      throw new NullPointerException(sb.toString());
    }

    PacketInstantiater instantiater = instantiaters.get(number);
    if (instantiater != null) {
      try {
        return instantiater.newInstance(rawData);
      } catch (IllegalRawDataException e) {
        return IllegalPacket.newPacket(rawData);
      }
    }

    return UnknownPacket.newPacket(rawData);
  }

  public Packet newInstance(byte[] rawData) {
    return UnknownPacket.newPacket(rawData);
  }

}
