package org.pcap4j.test;

import java.io.IOException;
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
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.ArpHardwareType;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.MacAddress;
import org.pcap4j.util.NifSelector;

public class SendPacketTest {

  private static final String COUNT_KEY
    = SendPacketTest.class.getName() + ".count";
  private static final int COUNT
    = Integer.getInteger(COUNT_KEY, 3);

  private static final String READ_TIMEOUT_KEY
    = SendPacketTest.class.getName() + ".readTimeOut";
  private static final int READ_TIMEOUT
    = Integer.getInteger(READ_TIMEOUT_KEY, 5); // [ms]

  private static final String MAX_PACKT_SIZE_KEY
    = SendPacketTest.class.getName() + ".maxPacketSize";
  private static final int MAX_PACKT_SIZE
    = Integer.getInteger(MAX_PACKT_SIZE_KEY, 65536); // [bytes]

  private static final MacAddress SRC_MAC_ADDR
   = MacAddress.getByAddress(
       new byte[] {(byte)0, (byte)1,(byte)2, (byte)3, (byte)4, (byte)5}
     );

  public static void main(String[] args) throws PcapNativeException {
    String strSrcIpAddress = args[0]; // for InetAddress.getByName()
    String strDstIpAddress = args[1]; // for InetAddress.getByName()

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

    try {
      try {
        handle.setFilter(
          "arp and src host " + strDstIpAddress
            + " and dst host " + strSrcIpAddress
            + " and ether dst " + Pcaps.toBpfString(SRC_MAC_ADDR),
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

      ArpPacket.Builder arpBuilder = new ArpPacket.Builder();
      try {
        arpBuilder.hardwareType(ArpHardwareType.ETHERNET)
          .protocolType(EtherType.IP_V4)
          .hardwareLength((byte)MacAddress.SIZE_IN_BYTES)
          .protocolLength((byte)ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES)
          .operation(ArpOperation.REQUEST)
          .srcHardwareAddr(SRC_MAC_ADDR)
          .srcProtocolAddr(InetAddress.getByName(strSrcIpAddress))
          .dstHardwareAddr(
             MacAddress.getByAddress(
               new byte[] {
                 (byte)255, (byte)255, (byte)255,
                 (byte)255, (byte)255, (byte)255
               }
             )
           )
          .dstProtocolAddr(InetAddress.getByName(strDstIpAddress));
      } catch (UnknownHostException e) {
        throw new IllegalArgumentException(e);
      }

      EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();
      etherBuilder.dstAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
                  .srcAddr(SRC_MAC_ADDR)
                  .type(EtherType.ARP)
                  .payloadBuilder(arpBuilder);

      for (int i = 0; i < COUNT; i++) {
        sendHandle.sendPacket(etherBuilder.build());
        try {
          Thread.sleep(1000);
        } catch (InterruptedException e) {
          break;
        }
      }
    } finally {
      if (handle != null && handle.isOpening()) {
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
        handle.loop(COUNT, listener);
      } catch (PcapNativeException e) {
        e.printStackTrace();
      } catch (InterruptedException e) {
        e.printStackTrace();
      }
    }

  }

}
