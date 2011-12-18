package org.pcap4j.test;


import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import org.pcap4j.core.Pcap;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.GotPacketEventListener;
import org.pcap4j.core.PcapHandle.BpfCompileMode;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.ArpPacket.ArpHeader;
import org.pcap4j.packet.EthernetPacket.EthernetHeader;
import org.pcap4j.packet.namedvalue.ArpHardwareType;
import org.pcap4j.packet.namedvalue.ArpOperation;
import org.pcap4j.packet.namedvalue.EtherType;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.MacAddress;


public class SendPacketTest {

  private static final String COUNT_KEY
    = LoopTest.class.getPackage().getName() + ".count";
  private static final int COUNT
    = Integer.getInteger(COUNT_KEY, 3);

  private static final String READ_TIMEOUT_KEY
    = LoopTest.class.getPackage().getName() + ".readTimeOut";
  private static final int READ_TIMEOUT
    = Integer.getInteger(READ_TIMEOUT_KEY, 5); // [ms]

  private static final String MAX_PACKT_SIZE_KEY
    = LoopTest.class.getPackage().getName() + ".maxPacketSize";
  private static final int MAX_PACKT_SIZE
    = Integer.getInteger(MAX_PACKT_SIZE_KEY, 65535); // [bytes]

  private static final MacAddress SRC_MAC_ADDR
   = MacAddress.newInstance(
       new byte[] {(byte)0, (byte)1,(byte)2, (byte)3, (byte)4, (byte)5}
     );
  public static void main(String[] args) throws PcapNativeException {
    BasicConfigurator.configure();
    Logger.getRootLogger().setLevel(Level.INFO);

    System.out.println(COUNT_KEY + ": " + COUNT);
    System.out.println(READ_TIMEOUT_KEY + ": " + READ_TIMEOUT);
    System.out.println(MAX_PACKT_SIZE_KEY + ": " + MAX_PACKT_SIZE);
    System.out.println("\n");

    PcapNetworkInterface nif;
    try {
      nif = Pcap.selectNetworkInterface(
              new InputStreamReader(System.in),
              new OutputStreamWriter(System.out)
            );
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
    ExecutorService pool = Executors.newSingleThreadExecutor();

    try {
      try {
        handle.setFilter(
          "arp and src host " + args[1]
            + " and dst host " + args[0]
            + " and ether dst " + PcapHandle.toBpfString(SRC_MAC_ADDR),
          BpfCompileMode.OPTIMIZE,
          InetAddress
            .getByAddress(new byte[] {(byte)255, (byte)255, (byte)255, (byte)0})
        );
      } catch (UnknownHostException e) {
        throw new AssertionError("Never get here.");
      }

      GotPacketEventListener listener
        = new GotPacketEventListener() {
            public void gotPacket(Packet packet) {
              System.out.println(packet);
            }
          };

      Task t = new Task(handle, listener);
      pool.execute(t);

      ArpPacket arpPacket = new ArpPacket();
      ArpHeader arpHeader = arpPacket.getHeader();
      arpHeader.setHardwareType(ArpHardwareType.ETHERNET);
      arpHeader.setProtocolType(EtherType.IPV4);
      arpHeader.setHardwareLength((byte)ByteArrays.MAC_ADDRESS_SIZE_IN_BYTE);
      arpHeader.setProtocolLength((byte)ByteArrays.IP_ADDRESS_SIZE_IN_BYTE);
      arpHeader.setOperation(ArpOperation.REQUEST);
      arpHeader.setSrcHardwareAddr(SRC_MAC_ADDR);
      try {
        arpHeader.setSrcProtocolAddr(InetAddress.getByName(args[0]));
      } catch (UnknownHostException e) {
        throw new IllegalArgumentException(e);
      }
      arpHeader.setDstHardwareAddr(
        MacAddress.newInstance(
          new byte[] {
            (byte)255, (byte)255, (byte)255, (byte)255, (byte)255, (byte)255
          }
        )
      );
      try {
        arpHeader.setDstProtocolAddr(InetAddress.getByName(args[1]));
      } catch (UnknownHostException e) {
        throw new IllegalArgumentException(e);
      }

      EthernetPacket etherPacket = new EthernetPacket();
      EthernetHeader etherHeader = etherPacket.getHeader();
      etherHeader.setDstAddr(
        MacAddress.newInstance(
          new byte[] {
            (byte)255, (byte)255, (byte)255, (byte)255, (byte)255, (byte)255
          }
        )
      );
      etherHeader.setSrcAddr(SRC_MAC_ADDR);
      etherHeader.setType(EtherType.ARP);
      etherPacket.setPayload(arpPacket);
      etherPacket.validate();

      for (int i = 0; i < COUNT; i++) {
        handle.sendPacket(etherPacket);
        try {
          Thread.sleep(1000);
        } catch (InterruptedException e) {
          break;
        }
      }
    } finally {
      if (handle.isOpening()) {
        handle.close();
      }
      if (!pool.isShutdown()) {
        pool.shutdown();
      }
    }
  }

  private static class Task implements Runnable {

    private PcapHandle handle;
    private GotPacketEventListener listener;

    public Task(PcapHandle handle, GotPacketEventListener listener) {
      this.handle = handle;
      this.listener = listener;
    }

    public void run() {
      try {
        handle.loop(COUNT, listener);
      } catch (PcapNativeException e) {
        e.printStackTrace();
      }
    }

  }

}
