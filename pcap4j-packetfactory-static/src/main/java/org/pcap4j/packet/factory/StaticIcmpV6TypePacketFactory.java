/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2014  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import org.pcap4j.packet.IcmpV6DestinationUnreachablePacket;
import org.pcap4j.packet.IcmpV6EchoReplyPacket;
import org.pcap4j.packet.IcmpV6EchoRequestPacket;
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
public final class StaticIcmpV6TypePacketFactory
extends AbstractStaticPacketFactory<IcmpV6Type> {

  private static final StaticIcmpV6TypePacketFactory INSTANCE
    = new StaticIcmpV6TypePacketFactory();

  private StaticIcmpV6TypePacketFactory() {
    instantiaters.put(
      IcmpV6Type.DESTINATION_UNREACHABLE, new PacketInstantiater() {
        @Override
        public Packet newInstance(byte[] rawData) throws IllegalRawDataException {
          return IcmpV6DestinationUnreachablePacket.newPacket(rawData);
        }
      }
    );
    instantiaters.put(
      IcmpV6Type.PACKET_TOO_BIG, new PacketInstantiater() {
        @Override
        public Packet newInstance(byte[] rawData) throws IllegalRawDataException {
          return IcmpV6PacketTooBigPacket.newPacket(rawData);
        }
      }
    );
    instantiaters.put(
      IcmpV6Type.TIME_EXCEEDED, new PacketInstantiater() {
        @Override
        public Packet newInstance(byte[] rawData) throws IllegalRawDataException {
          return IcmpV6TimeExceededPacket.newPacket(rawData);
        }
      }
    );
    instantiaters.put(
      IcmpV6Type.PARAMETER_PROBLEM, new PacketInstantiater() {
        @Override
        public Packet newInstance(byte[] rawData) throws IllegalRawDataException {
          return IcmpV6ParameterProblemPacket.newPacket(rawData);
        }
      }
    );
    instantiaters.put(
      IcmpV6Type.ECHO_REQUEST, new PacketInstantiater() {
        @Override
        public Packet newInstance(byte[] rawData) throws IllegalRawDataException {
          return IcmpV6EchoRequestPacket.newPacket(rawData);
        }
      }
    );
    instantiaters.put(
      IcmpV6Type.ECHO_REPLY, new PacketInstantiater() {
        @Override
        public Packet newInstance(byte[] rawData) throws IllegalRawDataException {
          return IcmpV6EchoReplyPacket.newPacket(rawData);
        }
      }
    );
    instantiaters.put(
      IcmpV6Type.ROUTER_SOLICITATION, new PacketInstantiater() {
        @Override
        public Packet newInstance(byte[] rawData) throws IllegalRawDataException {
          return IcmpV6RouterSolicitationPacket.newPacket(rawData);
        }
      }
    );
    instantiaters.put(
      IcmpV6Type.ROUTER_ADVERTISEMENT, new PacketInstantiater() {
        @Override
        public Packet newInstance(byte[] rawData) throws IllegalRawDataException {
          return IcmpV6RouterAdvertisementPacket.newPacket(rawData);
        }
      }
    );
    instantiaters.put(
      IcmpV6Type.NEIGHBOR_SOLICITATION, new PacketInstantiater() {
        @Override
        public Packet newInstance(byte[] rawData) throws IllegalRawDataException {
          return IcmpV6NeighborSolicitationPacket.newPacket(rawData);
        }
      }
    );
    instantiaters.put(
      IcmpV6Type.NEIGHBOR_ADVERTISEMENT, new PacketInstantiater() {
        @Override
        public Packet newInstance(byte[] rawData) throws IllegalRawDataException {
          return IcmpV6NeighborAdvertisementPacket.newPacket(rawData);
        }
      }
    );
    instantiaters.put(
      IcmpV6Type.REDIRECT, new PacketInstantiater() {
        @Override
        public Packet newInstance(byte[] rawData) throws IllegalRawDataException {
          return IcmpV6RedirectPacket.newPacket(rawData);
        }
      }
    );
  };

  /**
   *
   * @return the singleton instance of StaticIcmpV6TypePacketFactory.
   */
  public static StaticIcmpV6TypePacketFactory getInstance() {
    return INSTANCE;
  }

}
