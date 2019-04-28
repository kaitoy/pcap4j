/*_##########################################################################
  _##
  _##  Copyright (C) 2014-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory.statik;

import org.pcap4j.packet.CompressedPacket;
import org.pcap4j.packet.EncryptedPacket;
import org.pcap4j.packet.FragmentedPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV6ExtUnknownPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.NotApplicable;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.4.0
 */
public final class StaticNotApplicablePacketFactory
    extends AbstractStaticPacketFactory<NotApplicable> {

  private static final StaticNotApplicablePacketFactory INSTANCE =
      new StaticNotApplicablePacketFactory();

  private StaticNotApplicablePacketFactory() {
    instantiaters.put(
        NotApplicable.UNKNOWN,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length) {
            return UnknownPacket.newPacket(rawData, offset, length);
          }

          @Override
          public Class<UnknownPacket> getTargetClass() {
            return UnknownPacket.class;
          }
        });
    instantiaters.put(
        NotApplicable.FRAGMENTED,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length) {
            return FragmentedPacket.newPacket(rawData, offset, length);
          }

          @Override
          public Class<FragmentedPacket> getTargetClass() {
            return FragmentedPacket.class;
          }
        });
    instantiaters.put(
        NotApplicable.UNKNOWN_IP_V6_EXTENSION,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return IpV6ExtUnknownPacket.newPacket(rawData, offset, length);
          }

          @Override
          public Class<IpV6ExtUnknownPacket> getTargetClass() {
            return IpV6ExtUnknownPacket.class;
          }
        });
    instantiaters.put(
        NotApplicable.COMPRESSED,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length) {
            return CompressedPacket.newPacket(rawData, offset, length);
          }

          @Override
          public Class<CompressedPacket> getTargetClass() {
            return CompressedPacket.class;
          }
        });
    instantiaters.put(
        NotApplicable.ENCRYPTED,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length) {
            return EncryptedPacket.newPacket(rawData, offset, length);
          }

          @Override
          public Class<EncryptedPacket> getTargetClass() {
            return EncryptedPacket.class;
          }
        });
  }

  /** @return the singleton instance of StaticNaPacketFactory. */
  public static StaticNotApplicablePacketFactory getInstance() {
    return INSTANCE;
  }
}
