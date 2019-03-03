/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory.statik;

import org.pcap4j.packet.IcmpV6DestinationUnreachablePacket;
import org.pcap4j.packet.IcmpV6EchoReplyPacket;
import org.pcap4j.packet.IcmpV6EchoRequestPacket;
import org.pcap4j.packet.IcmpV6HomeAgentAddressDiscoveryReplyPacket;
import org.pcap4j.packet.IcmpV6HomeAgentAddressDiscoveryRequestPacket;
import org.pcap4j.packet.IcmpV6MobilePrefixAdvertisementPacket;
import org.pcap4j.packet.IcmpV6MobilePrefixSolicitationPacket;
import org.pcap4j.packet.IcmpV6NeighborAdvertisementPacket;
import org.pcap4j.packet.IcmpV6NeighborSolicitationPacket;
import org.pcap4j.packet.IcmpV6PacketTooBigPacket;
import org.pcap4j.packet.IcmpV6ParameterProblemPacket;
import org.pcap4j.packet.IcmpV6RedirectPacket;
import org.pcap4j.packet.IcmpV6RouterAdvertisementPacket;
import org.pcap4j.packet.IcmpV6RouterSolicitationPacket;
import org.pcap4j.packet.IcmpV6TimeExceededPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.IcmpV6Type;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.15
 */
public final class StaticIcmpV6TypePacketFactory extends AbstractStaticPacketFactory<IcmpV6Type> {

  private static final StaticIcmpV6TypePacketFactory INSTANCE = new StaticIcmpV6TypePacketFactory();

  private StaticIcmpV6TypePacketFactory() {
    instantiaters.put(
        IcmpV6Type.DESTINATION_UNREACHABLE,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return IcmpV6DestinationUnreachablePacket.newPacket(rawData, offset, length);
          }

          @Override
          public Class<IcmpV6DestinationUnreachablePacket> getTargetClass() {
            return IcmpV6DestinationUnreachablePacket.class;
          }
        });
    instantiaters.put(
        IcmpV6Type.PACKET_TOO_BIG,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return IcmpV6PacketTooBigPacket.newPacket(rawData, offset, length);
          }

          @Override
          public Class<IcmpV6PacketTooBigPacket> getTargetClass() {
            return IcmpV6PacketTooBigPacket.class;
          }
        });
    instantiaters.put(
        IcmpV6Type.TIME_EXCEEDED,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return IcmpV6TimeExceededPacket.newPacket(rawData, offset, length);
          }

          @Override
          public Class<IcmpV6TimeExceededPacket> getTargetClass() {
            return IcmpV6TimeExceededPacket.class;
          }
        });
    instantiaters.put(
        IcmpV6Type.PARAMETER_PROBLEM,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return IcmpV6ParameterProblemPacket.newPacket(rawData, offset, length);
          }

          @Override
          public Class<IcmpV6ParameterProblemPacket> getTargetClass() {
            return IcmpV6ParameterProblemPacket.class;
          }
        });
    instantiaters.put(
        IcmpV6Type.ECHO_REQUEST,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return IcmpV6EchoRequestPacket.newPacket(rawData, offset, length);
          }

          @Override
          public Class<IcmpV6EchoRequestPacket> getTargetClass() {
            return IcmpV6EchoRequestPacket.class;
          }
        });
    instantiaters.put(
        IcmpV6Type.ECHO_REPLY,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return IcmpV6EchoReplyPacket.newPacket(rawData, offset, length);
          }

          @Override
          public Class<IcmpV6EchoReplyPacket> getTargetClass() {
            return IcmpV6EchoReplyPacket.class;
          }
        });
    instantiaters.put(
        IcmpV6Type.ROUTER_SOLICITATION,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return IcmpV6RouterSolicitationPacket.newPacket(rawData, offset, length);
          }

          @Override
          public Class<IcmpV6RouterSolicitationPacket> getTargetClass() {
            return IcmpV6RouterSolicitationPacket.class;
          }
        });
    instantiaters.put(
        IcmpV6Type.ROUTER_ADVERTISEMENT,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return IcmpV6RouterAdvertisementPacket.newPacket(rawData, offset, length);
          }

          @Override
          public Class<IcmpV6RouterAdvertisementPacket> getTargetClass() {
            return IcmpV6RouterAdvertisementPacket.class;
          }
        });
    instantiaters.put(
        IcmpV6Type.NEIGHBOR_SOLICITATION,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return IcmpV6NeighborSolicitationPacket.newPacket(rawData, offset, length);
          }

          @Override
          public Class<IcmpV6NeighborSolicitationPacket> getTargetClass() {
            return IcmpV6NeighborSolicitationPacket.class;
          }
        });
    instantiaters.put(
        IcmpV6Type.NEIGHBOR_ADVERTISEMENT,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return IcmpV6NeighborAdvertisementPacket.newPacket(rawData, offset, length);
          }

          @Override
          public Class<IcmpV6NeighborAdvertisementPacket> getTargetClass() {
            return IcmpV6NeighborAdvertisementPacket.class;
          }
        });
    instantiaters.put(
        IcmpV6Type.REDIRECT,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return IcmpV6RedirectPacket.newPacket(rawData, offset, length);
          }

          @Override
          public Class<IcmpV6RedirectPacket> getTargetClass() {
            return IcmpV6RedirectPacket.class;
          }
        });
    instantiaters.put(
        IcmpV6Type.HOME_AGENT_ADDRESS_DISCOVERY_REQUEST,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return IcmpV6HomeAgentAddressDiscoveryRequestPacket.newPacket(rawData, offset, length);
          }

          @Override
          public Class<IcmpV6HomeAgentAddressDiscoveryRequestPacket> getTargetClass() {
            return IcmpV6HomeAgentAddressDiscoveryRequestPacket.class;
          }
        });
    instantiaters.put(
        IcmpV6Type.HOME_AGENT_ADDRESS_DISCOVERY_REPLY,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return IcmpV6HomeAgentAddressDiscoveryReplyPacket.newPacket(rawData, offset, length);
          }

          @Override
          public Class<IcmpV6HomeAgentAddressDiscoveryReplyPacket> getTargetClass() {
            return IcmpV6HomeAgentAddressDiscoveryReplyPacket.class;
          }
        });
    instantiaters.put(
        IcmpV6Type.MOBILE_PREFIX_SOLICITATION,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return IcmpV6MobilePrefixSolicitationPacket.newPacket(rawData, offset, length);
          }

          @Override
          public Class<IcmpV6MobilePrefixSolicitationPacket> getTargetClass() {
            return IcmpV6MobilePrefixSolicitationPacket.class;
          }
        });
    instantiaters.put(
        IcmpV6Type.MOBILE_PREFIX_ADVERTISEMENT,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return IcmpV6MobilePrefixAdvertisementPacket.newPacket(rawData, offset, length);
          }

          @Override
          public Class<IcmpV6MobilePrefixAdvertisementPacket> getTargetClass() {
            return IcmpV6MobilePrefixAdvertisementPacket.class;
          }
        });
  }

  /** @return the singleton instance of StaticIcmpV6TypePacketFactory. */
  public static StaticIcmpV6TypePacketFactory getInstance() {
    return INSTANCE;
  }
}
