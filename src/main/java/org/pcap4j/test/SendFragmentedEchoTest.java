package org.pcap4j.test;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle.BpfCompileMode;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.AbstractPacket.AbstractBuilder;
import org.pcap4j.packet.AnonymousPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IcmpV4Packet;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IcmpV4TypeCode;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.util.IpV4Helper;
import org.pcap4j.util.MacAddress;
import org.pcap4j.util.NifSelector;

public class SendFragmentedEchoTest {

  private static final String COUNT_KEY
    = SendFragmentedEchoTest.class.getName() + ".count";
  private static final int COUNT
    = Integer.getInteger(COUNT_KEY, 3);

  private static final String READ_TIMEOUT_KEY
    = SendFragmentedEchoTest.class.getName() + ".readTimeOut";
  private static final int READ_TIMEOUT
    = Integer.getInteger(READ_TIMEOUT_KEY, 5); // [ms]

  private static final String MAX_PACKT_SIZE_KEY
    = SendFragmentedEchoTest.class.getName() + ".maxPacketSize";
  private static final int MAX_PACKT_SIZE
    = Integer.getInteger(MAX_PACKT_SIZE_KEY, 65536); // [bytes]

  private static final String TU_KEY
    = SendFragmentedEchoTest.class.getName() + ".tu";
  private static final int TU
    = Integer.getInteger(TU_KEY, 4000); // [bytes]

  private static final String MTU_KEY
    = SendFragmentedEchoTest.class.getName() + ".mtu";
  private static final int MTU
    = Integer.getInteger(MTU_KEY, 1403); // [bytes]

  public static void main(String[] args) throws PcapNativeException {
    String strSrcIpAddress = args[0]; // for InetAddress.getByName()
    String strSrcMacAddress = args[1]; // e.g. 12:34:56:ab:cd:ef
    String strDstIpAddress = args[2]; // for InetAddress.getByName()
    String strDstMacAddress = args[3]; // e.g. 12:34:56:ab:cd:ef

    System.out.println(COUNT_KEY + ": " + COUNT);
    System.out.println(READ_TIMEOUT_KEY + ": " + READ_TIMEOUT);
    System.out.println(MAX_PACKT_SIZE_KEY + ": " + MAX_PACKT_SIZE);
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

    PcapHandle handle
      = nif.openLive(MAX_PACKT_SIZE, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
    PcapHandle sendHandle
      = nif.openLive(MAX_PACKT_SIZE, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
    ExecutorService pool = Executors.newSingleThreadExecutor();

    MacAddress srcMacAddr = MacAddress.getByName(strSrcMacAddress, ":");
    try {
      try {
        handle.setFilter(
          "icmp and ether dst " + Pcaps.toBpfString(srcMacAddr),
          BpfCompileMode.OPTIMIZE,
          InetAddress
            .getByAddress(new byte[] {(byte)255, (byte)255, (byte)255, (byte)0})
        );
      } catch (UnknownHostException e) {
        throw new AssertionError("Never get here.");
      }

      PacketListener listener
        = new PacketListener() {
            public void gotPacket(Packet packet) {
              System.out.println(packet);
            }
          };

      Task t = new Task(handle, listener);
      pool.execute(t);

      byte[] echoData = new byte[TU - 28];
      for (int i = 0; i < echoData.length; i++) {
        echoData[i] = (byte)i;
      }

      IcmpV4Packet.Builder echoBuilder = new IcmpV4Packet.Builder();
      echoBuilder.typeCode(IcmpV4TypeCode.ECHO)
                 .identifier((short)1)
                 .payloadBuilder(new AnonymousPacket.Builder().rawData(echoData));

      IpV4Packet.Builder ipV4Builder = new IpV4Packet.Builder();
      try {
        ipV4Builder.ttl((byte)100)
                   .protocol(IpNumber.ICMP_V4)
                   .srcAddr((Inet4Address)InetAddress.getByName(strSrcIpAddress))
                   .dstAddr((Inet4Address)InetAddress.getByName(strDstIpAddress))
                   .payloadBuilder(echoBuilder);
      } catch (UnknownHostException e1) {
        throw new IllegalArgumentException(e1);
      }

      EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();
      etherBuilder.dstAddr(MacAddress.getByName(strDstMacAddress, ":"))
                  .srcAddr(srcMacAddr)
                  .type(EtherType.IP_V4);

      for (int i = 0; i < COUNT; i++) {
        echoBuilder.sequenceNumber((short)i);
        ipV4Builder.identification((short)i);

        for (
          final Packet ipV4Packet: IpV4Helper.fragment(ipV4Builder.build(), MTU)
        ) {
          etherBuilder.payloadBuilder(
            new AbstractBuilder() {
              public Packet build() {
                return ipV4Packet;
              }
            }
          );

          Packet p = etherBuilder.build();
          sendHandle.sendPacket(p);
          //System.out.println("Sent a echo:\n" + p);

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
      if (handle != null && handle.isOpening()) {
        handle.breakLoop();
        try {
          Thread.sleep(1000);
        } catch (InterruptedException e) {}
        handle.close();
      }
      if (sendHandle != null && sendHandle.isOpening()) {
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

    public void run() {
      try {
        handle.loop(-1, listener);
      } catch (PcapNativeException e) {
        e.printStackTrace();
      } catch (InterruptedException e) {}
    }

  }

}
