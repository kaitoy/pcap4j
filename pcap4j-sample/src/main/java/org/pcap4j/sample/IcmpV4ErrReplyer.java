package org.pcap4j.sample;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IcmpV4DestinationUnreachablePacket;
import org.pcap4j.packet.IcmpV4EchoPacket;
import org.pcap4j.packet.IcmpV4ParameterProblemPacket;
import org.pcap4j.packet.IcmpV4TimeExceededPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Rfc791Tos;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IcmpV4Code;
import org.pcap4j.packet.namednumber.IcmpV4Type;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.util.IcmpV4Helper;
import org.pcap4j.util.MacAddress;
import org.pcap4j.util.NifSelector;

@SuppressWarnings("javadoc")
public class IcmpV4ErrReplyer {

  private static MacAddress MAC_ADDR = MacAddress.getByName("fe:00:00:00:00:01");

  private IcmpV4ErrReplyer() {}

  public static void main(String[] args) throws PcapNativeException, NotOpenException {
    String strAddress = args[0];
    String strType =
        args[1]; // 3(DESTINATION_UNREACHABLE) or 11(TIME_EXCEEDED) or 12(PARAMETER_PROBLEM)
    String strCode = args[2];

    final Inet4Address address;
    try {
      address = (Inet4Address) InetAddress.getByName(strAddress);
    } catch (UnknownHostException e1) {
      throw new IllegalArgumentException("args[0]: " + strAddress);
    }

    final IcmpV4Type type;
    try {
      type = IcmpV4Type.getInstance(Byte.parseByte(strType));
    } catch (NumberFormatException e) {
      throw new IllegalArgumentException("args[1]: " + strType, e);
    }
    if (!type.equals(IcmpV4Type.DESTINATION_UNREACHABLE)
        && !type.equals(IcmpV4Type.TIME_EXCEEDED)
        && !type.equals(IcmpV4Type.PARAMETER_PROBLEM)) {
      throw new IllegalArgumentException("args[1]: " + strType);
    }

    IcmpV4Code code;
    try {
      code = IcmpV4Code.getInstance(type.value(), Byte.parseByte(strCode));
    } catch (NumberFormatException e) {
      throw new IllegalArgumentException("args[1]: " + strType, e);
    }

    PcapNetworkInterface nif;
    try {
      nif = new NifSelector().selectNetworkInterface();
    } catch (IOException e) {
      e.printStackTrace();
      return;
    }

    if (nif == null) {
      return;
    }

    System.out.println(nif.getName() + "(" + nif.getDescription() + ")");

    final PcapHandle handle4capture = nif.openLive(65536, PromiscuousMode.PROMISCUOUS, 10);

    final PcapHandle handle4send = nif.openLive(65536, PromiscuousMode.PROMISCUOUS, 10);

    handle4capture.setFilter(
        "(ether dst "
            + MAC_ADDR
            + ") or (arp and ether dst "
            + Pcaps.toBpfString(MacAddress.ETHER_BROADCAST_ADDRESS)
            + ")",
        BpfCompileMode.OPTIMIZE);

    Packet.Builder tmp;
    if (type.equals(IcmpV4Type.DESTINATION_UNREACHABLE)) {
      tmp = new IcmpV4DestinationUnreachablePacket.Builder();
    } else if (type.equals(IcmpV4Type.TIME_EXCEEDED)) {
      tmp = new IcmpV4TimeExceededPacket.Builder();
    } else if (type.equals(IcmpV4Type.PARAMETER_PROBLEM)) {
      tmp = new IcmpV4ParameterProblemPacket.Builder();
    } else {
      throw new AssertionError();
    }

    final Packet.Builder icmpV4errb = tmp;

    IcmpV4CommonPacket.Builder icmpV4b = new IcmpV4CommonPacket.Builder();
    icmpV4b.type(type).code(code).payloadBuilder(icmpV4errb).correctChecksumAtBuild(true);

    final IpV4Packet.Builder ipv4b = new IpV4Packet.Builder();
    ipv4b
        .version(IpVersion.IPV4)
        .tos(IpV4Rfc791Tos.newInstance((byte) 0))
        .identification((short) 100)
        .ttl((byte) 100)
        .protocol(IpNumber.ICMPV4)
        .payloadBuilder(icmpV4b)
        .correctChecksumAtBuild(true)
        .correctLengthAtBuild(true);

    final EthernetPacket.Builder eb = new EthernetPacket.Builder();
    eb.type(EtherType.IPV4).payloadBuilder(ipv4b).paddingAtBuild(true);

    final PacketListener listener =
        new PacketListener() {
          public void gotPacket(Packet packet) {
            if (packet.contains(IcmpV4EchoPacket.class)) {
              if (type.equals(IcmpV4Type.DESTINATION_UNREACHABLE)) {
                ((IcmpV4DestinationUnreachablePacket.Builder) icmpV4errb)
                    .payload(
                        IcmpV4Helper.makePacketForInvokingPacketField(
                            packet.get(IpV4Packet.class)));
              } else if (type.equals(IcmpV4Type.TIME_EXCEEDED)) {
                ((IcmpV4TimeExceededPacket.Builder) icmpV4errb)
                    .payload(
                        IcmpV4Helper.makePacketForInvokingPacketField(
                            packet.get(IpV4Packet.class)));
              } else if (type.equals(IcmpV4Type.PARAMETER_PROBLEM)) {
                ((IcmpV4ParameterProblemPacket.Builder) icmpV4errb)
                    .payload(
                        IcmpV4Helper.makePacketForInvokingPacketField(
                            packet.get(IpV4Packet.class)));
              }

              ipv4b.srcAddr(packet.get(IpV4Packet.class).getHeader().getDstAddr());
              ipv4b.dstAddr(packet.get(IpV4Packet.class).getHeader().getSrcAddr());
              eb.srcAddr(packet.get(EthernetPacket.class).getHeader().getDstAddr());
              eb.dstAddr(packet.get(EthernetPacket.class).getHeader().getSrcAddr());

              try {
                handle4send.sendPacket(eb.build());
              } catch (PcapNativeException e) {
                e.printStackTrace();
              } catch (NotOpenException e) {
                e.printStackTrace();
              }
            } else if (packet.contains(ArpPacket.class)) {
              ArpPacket ap = packet.get(ArpPacket.class);

              if (!ap.getHeader().getOperation().equals(ArpOperation.REQUEST)) {
                return;
              }
              if (!ap.getHeader().getDstProtocolAddr().equals(address)) {
                return;
              }

              EthernetPacket.Builder eb = (EthernetPacket.Builder) packet.getBuilder();
              ArpPacket.Builder ab = eb.get(ArpPacket.Builder.class);

              ab.srcHardwareAddr(MAC_ADDR)
                  .dstHardwareAddr(ap.getHeader().getSrcHardwareAddr())
                  .srcProtocolAddr(ap.getHeader().getDstProtocolAddr())
                  .dstProtocolAddr(ap.getHeader().getSrcProtocolAddr())
                  .operation(ArpOperation.REPLY);

              eb.dstAddr(ap.getHeader().getSrcHardwareAddr()).srcAddr(MAC_ADDR);

              try {
                handle4send.sendPacket(eb.build());
              } catch (PcapNativeException e) {
                e.printStackTrace();
              } catch (NotOpenException e) {
                e.printStackTrace();
              }
            }
          }
        };

    ExecutorService executor = Executors.newSingleThreadExecutor();
    executor.execute(
        new Runnable() {
          public void run() {
            while (true) {
              try {
                handle4capture.loop(-1, listener);
              } catch (PcapNativeException e) {
                e.printStackTrace();
              } catch (InterruptedException e) {
                break;
              } catch (NotOpenException e) {
                break;
              }
            }
          }
        });

    block();
    handle4capture.breakLoop();

    handle4capture.close();
    handle4send.close();
    executor.shutdown();
  }

  private static void block() {
    try {
      Thread.sleep(2000);
    } catch (InterruptedException e1) {
    }

    BufferedReader r = null;

    try {
      r = new BufferedReader(new InputStreamReader(System.in));
      System.out.println("** Hit Enter key to stop simulation **");
      r.readLine();
    } catch (IOException e) {
      e.printStackTrace();
    } finally {
      try {
        if (r != null) {
          r.close();
        }
      } catch (IOException e) {
      }
    }
  }
}
