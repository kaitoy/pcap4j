/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory.statik;

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
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.IcmpV4Type;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.14
 */
public final class StaticIcmpV4TypePacketFactory extends AbstractStaticPacketFactory<IcmpV4Type> {

  private static final StaticIcmpV4TypePacketFactory INSTANCE = new StaticIcmpV4TypePacketFactory();

  private StaticIcmpV4TypePacketFactory() {
    instantiaters.put(
        IcmpV4Type.ECHO_REPLY,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return IcmpV4EchoReplyPacket.newPacket(rawData, offset, length);
          }

          @Override
          public Class<IcmpV4EchoReplyPacket> getTargetClass() {
            return IcmpV4EchoReplyPacket.class;
          }
        });
    instantiaters.put(
        IcmpV4Type.DESTINATION_UNREACHABLE,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return IcmpV4DestinationUnreachablePacket.newPacket(rawData, offset, length);
          }

          @Override
          public Class<IcmpV4DestinationUnreachablePacket> getTargetClass() {
            return IcmpV4DestinationUnreachablePacket.class;
          }
        });
    instantiaters.put(
        IcmpV4Type.SOURCE_QUENCH,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return IcmpV4SourceQuenchPacket.newPacket(rawData, offset, length);
          }

          @Override
          public Class<IcmpV4SourceQuenchPacket> getTargetClass() {
            return IcmpV4SourceQuenchPacket.class;
          }
        });
    instantiaters.put(
        IcmpV4Type.REDIRECT,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return IcmpV4RedirectPacket.newPacket(rawData, offset, length);
          }

          @Override
          public Class<IcmpV4RedirectPacket> getTargetClass() {
            return IcmpV4RedirectPacket.class;
          }
        });
    instantiaters.put(
        IcmpV4Type.ECHO,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return IcmpV4EchoPacket.newPacket(rawData, offset, length);
          }

          @Override
          public Class<IcmpV4EchoPacket> getTargetClass() {
            return IcmpV4EchoPacket.class;
          }
        });
    instantiaters.put(
        IcmpV4Type.TIME_EXCEEDED,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return IcmpV4TimeExceededPacket.newPacket(rawData, offset, length);
          }

          @Override
          public Class<IcmpV4TimeExceededPacket> getTargetClass() {
            return IcmpV4TimeExceededPacket.class;
          }
        });
    instantiaters.put(
        IcmpV4Type.PARAMETER_PROBLEM,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return IcmpV4ParameterProblemPacket.newPacket(rawData, offset, length);
          }

          @Override
          public Class<IcmpV4ParameterProblemPacket> getTargetClass() {
            return IcmpV4ParameterProblemPacket.class;
          }
        });
    instantiaters.put(
        IcmpV4Type.TIMESTAMP,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return IcmpV4TimestampPacket.newPacket(rawData, offset, length);
          }

          @Override
          public Class<IcmpV4TimestampPacket> getTargetClass() {
            return IcmpV4TimestampPacket.class;
          }
        });
    instantiaters.put(
        IcmpV4Type.TIMESTAMP_REPLY,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return IcmpV4TimestampReplyPacket.newPacket(rawData, offset, length);
          }

          @Override
          public Class<IcmpV4TimestampReplyPacket> getTargetClass() {
            return IcmpV4TimestampReplyPacket.class;
          }
        });
    instantiaters.put(
        IcmpV4Type.INFORMATION_REQUEST,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return IcmpV4InformationRequestPacket.newPacket(rawData, offset, length);
          }

          @Override
          public Class<IcmpV4InformationRequestPacket> getTargetClass() {
            return IcmpV4InformationRequestPacket.class;
          }
        });
    instantiaters.put(
        IcmpV4Type.INFORMATION_REPLY,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return IcmpV4InformationReplyPacket.newPacket(rawData, offset, length);
          }

          @Override
          public Class<IcmpV4InformationReplyPacket> getTargetClass() {
            return IcmpV4InformationReplyPacket.class;
          }
        });
  }

  /** @return the singleton instance of StaticIcmpV4TypePacketFactory. */
  public static StaticIcmpV4TypePacketFactory getInstance() {
    return INSTANCE;
  }
}
