package org.pcap4j.sample;

import java.io.IOException;
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
import org.pcap4j.packet.AbstractPacket.AbstractBuilder;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IcmpV4EchoPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Rfc791Tos;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IcmpV4Code;
import org.pcap4j.packet.namednumber.IcmpV4Type;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.util.IpV4Helper;
import org.pcap4j.util.MacAddress;
import org.pcap4j.util.NifSelector;

@SuppressWarnings("javadoc")
public class SendFragmentedEcho {

  private static final String COUNT_KEY = SendFragmentedEcho.class.getName() + ".count";
  private static final int COUNT = Integer.getInteger(COUNT_KEY, 3);

  private static final String READ_TIMEOUT_KEY =
      SendFragmentedEcho.class.getName() + ".readTimeout";
  private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]

  private static final String SNAPLEN_KEY = SendFragmentedEcho.class.getName() + ".snaplen";
  private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]

  private static final String TU_KEY = SendFragmentedEcho.class.getName() + ".tu";
  private static final int TU = Integer.getInteger(TU_KEY, 4000); // [bytes]

  private static final String MTU_KEY = SendFragmentedEcho.class.getName() + ".mtu";
  private static final int MTU = Integer.getInteger(MTU_KEY, 1403); // [bytes]

  private SendFragmentedEcho() {}

  public static void main(String[] args) throws PcapNativeException {
    String strSrcIpAddress = args[0]; // for InetAddress.getByName()
    String strSrcMacAddress = args[1]; // e.g. 12:34:56:ab:cd:ef
    String strDstIpAddress = args[2]; // for InetAddress.getByName()
    String strDstMacAddress = args[3]; // e.g. 12:34:56:ab:cd:ef

    System.out.println(COUNT_KEY + ": " + COUNT);
    System.out.println(READ_TIMEOUT_KEY + ": " + READ_TIMEOUT);
    System.out.println(SNAPLEN_KEY + ": " + SNAPLEN);
    System.out.println("\n");

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

    PcapHandle handle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
    PcapHandle sendHandle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
    ExecutorService pool = Executors.newSingleThreadExecutor();

    MacAddress srcMacAddr = MacAddress.getByName(strSrcMacAddress, ":");
    try {
      handle.setFilter(
          "icmp and ether dst " + Pcaps.toBpfString(srcMacAddr), BpfCompileMode.OPTIMIZE);

      PacketListener listener =
          new PacketListener() {
            @Override
            public void gotPacket(Packet packet) {
              System.out.println(packet);
            }
          };

      Task t = new Task(handle, listener);
      pool.execute(t);

      byte[] echoData = new byte[TU - 28];
      for (int i = 0; i < echoData.length; i++) {
        echoData[i] = (byte) i;
      }

      IcmpV4EchoPacket.Builder echoBuilder = new IcmpV4EchoPacket.Builder();
      echoBuilder
          .identifier((short) 1)
          .payloadBuilder(new UnknownPacket.Builder().rawData(echoData));

      IcmpV4CommonPacket.Builder icmpV4CommonBuilder = new IcmpV4CommonPacket.Builder();
      icmpV4CommonBuilder
          .type(IcmpV4Type.ECHO)
          .code(IcmpV4Code.NO_CODE)
          .payloadBuilder(echoBuilder)
          .correctChecksumAtBuild(true);

      IpV4Packet.Builder ipV4Builder = new IpV4Packet.Builder();
      try {
        ipV4Builder
            .version(IpVersion.IPV4)
            .tos(IpV4Rfc791Tos.newInstance((byte) 0))
            .ttl((byte) 100)
            .protocol(IpNumber.ICMPV4)
            .srcAddr((Inet4Address) InetAddress.getByName(strSrcIpAddress))
            .dstAddr((Inet4Address) InetAddress.getByName(strDstIpAddress))
            .payloadBuilder(icmpV4CommonBuilder)
            .correctChecksumAtBuild(true)
            .correctLengthAtBuild(true);
      } catch (UnknownHostException e1) {
        throw new IllegalArgumentException(e1);
      }

      EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();
      etherBuilder
          .dstAddr(MacAddress.getByName(strDstMacAddress, ":"))
          .srcAddr(srcMacAddr)
          .type(EtherType.IPV4)
          .paddingAtBuild(true);

      for (int i = 0; i < COUNT; i++) {
        echoBuilder.sequenceNumber((short) i);
        ipV4Builder.identification((short) i);

        for (final Packet ipV4Packet : IpV4Helper.fragment(ipV4Builder.build(), MTU)) {
          etherBuilder.payloadBuilder(
              new AbstractBuilder() {
                @Override
                public Packet build() {
                  return ipV4Packet;
                }
              });

          Packet p = etherBuilder.build();
          sendHandle.sendPacket(p);

          try {
            Thread.sleep(100);
          } catch (InterruptedException e) {
            break;
          }
        }

        try {
          Thread.sleep(1000);
        } catch (InterruptedException e) {
          break;
        }
      }
    } catch (Exception e) {
      e.printStackTrace();
    } finally {
      if (handle != null && handle.isOpen()) {
        try {
          handle.breakLoop();
        } catch (NotOpenException noe) {
        }
        try {
          Thread.sleep(1000);
        } catch (InterruptedException e) {
        }
        handle.close();
      }
      if (sendHandle != null && sendHandle.isOpen()) {
        sendHandle.close();
      }
      if (pool != null && !pool.isShutdown()) {
        pool.shutdown();
      }
    }
  }

  private static class Task implements Runnable {

    private PcapHandle handle;
    private PacketListener listener;

    public Task(PcapHandle handle, PacketListener listener) {
      this.handle = handle;
      this.listener = listener;
    }

    @Override
    public void run() {
      try {
        handle.loop(-1, listener);
      } catch (PcapNativeException e) {
        e.printStackTrace();
      } catch (InterruptedException e) {
      } catch (NotOpenException e) {
        e.printStackTrace();
      }
    }
  }
}
