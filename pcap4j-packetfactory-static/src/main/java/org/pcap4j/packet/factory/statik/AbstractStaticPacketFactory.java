/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory.statik;

import java.util.HashMap;
import java.util.Map;
import org.pcap4j.packet.IllegalPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.factory.PacketFactory;
import org.pcap4j.packet.namednumber.NamedNumber;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.16
 * @param <N> number
 */
public abstract class AbstractStaticPacketFactory<N extends NamedNumber<?, ?>>
    implements PacketFactory<Packet, N> {

  /** */
  protected final Map<N, PacketInstantiater> instantiaters = new HashMap<N, PacketInstantiater>();

  @Override
  public Packet newInstance(byte[] rawData, int offset, int length, N number) {
    if (rawData == null || number == null) {
      StringBuilder sb = new StringBuilder(40);
      sb.append("rawData: ").append(rawData).append(" number: ").append(number);
      throw new NullPointerException(sb.toString());
    }

    PacketInstantiater instantiater = instantiaters.get(number);
    if (instantiater != null) {
      try {
        return instantiater.newInstance(rawData, offset, length);
      } catch (IllegalRawDataException e) {
        return IllegalPacket.newPacket(rawData, offset, length);
      }
    }

    return newInstance(rawData, offset, length);
  }

  @Override
  public Packet newInstance(byte[] rawData, int offset, int length) {
    return UnknownPacket.newPacket(rawData, offset, length);
  }

  @Override
  public Class<? extends Packet> getTargetClass(N number) {
    if (number == null) {
      throw new NullPointerException("number must not be null.");
    }
    PacketInstantiater pi = instantiaters.get(number);
    return pi != null ? pi.getTargetClass() : getTargetClass();
  }

  @Override
  public Class<? extends Packet> getTargetClass() {
    return UnknownPacket.class;
  }
}
