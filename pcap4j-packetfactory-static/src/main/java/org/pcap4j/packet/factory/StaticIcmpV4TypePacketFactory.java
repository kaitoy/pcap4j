/*_##########################################################################
  _##
  _##  Copyright (C) 2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import org.pcap4j.packet.IcmpV4DestinationUnreachablePacket;
import org.pcap4j.packet.IcmpV4EchoPacket;
import org.pcap4j.packet.IcmpV4EchoReplyPacket;
import org.pcap4j.packet.IcmpV4InformationReplyPacket;
import org.pcap4j.packet.IcmpV4InformationRequestPacket;
import org.pcap4j.packet.IcmpV4ParameterProblemPacket;
import org.pcap4j.packet.IcmpV4RedirectPacket;
import org.pcap4j.packet.IcmpV4SourceQuenchPacket;
import org.pcap4j.packet.IcmpV4TimeExceededPacket;
import org.pcap4j.packet.IcmpV4TimestampPacket;
import org.pcap4j.packet.IcmpV4TimestampReplyPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.IcmpV4Type;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.14
 */
public final class StaticIcmpV4TypePacketFactory
extends AbstractStaticPacketFactory<IcmpV4Type> {

  private static final StaticIcmpV4TypePacketFactory INSTANCE
    = new StaticIcmpV4TypePacketFactory();

  private StaticIcmpV4TypePacketFactory() {
    instantiaters.put(
      IcmpV4Type.ECHO_REPLY, new PacketInstantiater() {
        @Override
        public Packet newInstance(byte[] rawData) {
          return IcmpV4EchoReplyPacket.newPacket(rawData);
        }
      }
    );
    instantiaters.put(
      IcmpV4Type.DESTINATION_UNREACHABLE, new PacketInstantiater() {
        @Override
        public Packet newInstance(byte[] rawData) {
          return IcmpV4DestinationUnreachablePacket.newPacket(rawData);
        }
      }
    );
    instantiaters.put(
      IcmpV4Type.SOURCE_QUENCH, new PacketInstantiater() {
        @Override
        public Packet newInstance(byte[] rawData) {
          return IcmpV4SourceQuenchPacket.newPacket(rawData);
        }
      }
    );
    instantiaters.put(
      IcmpV4Type.REDIRECT, new PacketInstantiater() {
        @Override
        public Packet newInstance(byte[] rawData) {
          return IcmpV4RedirectPacket.newPacket(rawData);
        }
      }
    );
    instantiaters.put(
      IcmpV4Type.ECHO, new PacketInstantiater() {
        @Override
        public Packet newInstance(byte[] rawData) {
          return IcmpV4EchoPacket.newPacket(rawData);
        }
      }
    );
    instantiaters.put(
      IcmpV4Type.TIME_EXCEEDED, new PacketInstantiater() {
        @Override
        public Packet newInstance(byte[] rawData) {
          return IcmpV4TimeExceededPacket.newPacket(rawData);
        }
      }
    );
    instantiaters.put(
      IcmpV4Type.PARAMETER_PROBLEM, new PacketInstantiater() {
        @Override
        public Packet newInstance(byte[] rawData) {
          return IcmpV4ParameterProblemPacket.newPacket(rawData);
        }
      }
    );
    instantiaters.put(
      IcmpV4Type.TIMESTAMP, new PacketInstantiater() {
        @Override
        public Packet newInstance(byte[] rawData) {
          return IcmpV4TimestampPacket.newPacket(rawData);
        }
      }
    );
    instantiaters.put(
      IcmpV4Type.TIMESTAMP_REPLY, new PacketInstantiater() {
        @Override
        public Packet newInstance(byte[] rawData) {
          return IcmpV4TimestampReplyPacket.newPacket(rawData);
        }
      }
    );
    instantiaters.put(
      IcmpV4Type.INFORMATION_REQUEST, new PacketInstantiater() {
        @Override
        public Packet newInstance(byte[] rawData) {
          return IcmpV4InformationRequestPacket.newPacket(rawData);
        }
      }
    );
    instantiaters.put(
      IcmpV4Type.INFORMATION_REPLY, new PacketInstantiater() {
        @Override
        public Packet newInstance(byte[] rawData) {
          return IcmpV4InformationReplyPacket.newPacket(rawData);
        }
      }
    );
  };

  /**
   *
   * @return the singleton instance of StaticIcmpV4TypePacketFactory.
   */
  public static StaticIcmpV4TypePacketFactory getInstance() {
    return INSTANCE;
  }

}
