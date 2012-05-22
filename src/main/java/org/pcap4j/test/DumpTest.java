package org.pcap4j.test;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapHandle.BpfCompileMode;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.NifSelector;

public class DumpTest {

  private static final String COUNT_KEY
    = DumpTest.class.getName() + ".count";
  private static final int COUNT
    = Integer.getInteger(COUNT_KEY, 5);

  private static final String READ_TIMEOUT_KEY
    = DumpTest.class.getName() + ".readTimeOut";
  private static final int READ_TIMEOUT
    = Integer.getInteger(READ_TIMEOUT_KEY, 5); // [ms]

  private static final String MAX_PACKT_SIZE_KEY
    = DumpTest.class.getName() + ".maxPacketSize";
  private static final int MAX_PACKT_SIZE
    = Integer.getInteger(MAX_PACKT_SIZE_KEY, 65536); // [bytes]

  private static final String PCAP_FILE_KEY
    = DumpTest.class.getName() + ".pcapFile";
  private static final String PCAP_FILE
    = System.getProperty(PCAP_FILE_KEY, "DumpTest.pcap");

  public static void main(String[] args) throws PcapNativeException {
    String filter = args.length != 0 ? args[0] : "";

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

    try {
      handle.setFilter(
        filter,
        BpfCompileMode.OPTIMIZE,
        InetAddress
          .getByAddress(new byte[] {(byte)255, (byte)255, (byte)255, (byte)0})
      );
    } catch (UnknownHostException e) {
      assert true; // never get here
    }

    int num = 0;
    PcapDumper dumper = handle.dumpOpen(PCAP_FILE);
    while (true) {
      Packet packet = handle.getNextPacket();
      if (packet == null) {
        continue;
      }
      else {
        dumper.dump(packet, handle.getTimestampInts(), handle.getTimestampMicros());
        num++;
        if (num >= COUNT) {
          break;
        }
      }
    }

    dumper.close();
    handle.close();
  }

}
