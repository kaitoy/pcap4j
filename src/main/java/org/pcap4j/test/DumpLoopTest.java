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
import org.pcap4j.util.NifSelector;

public class DumpLoopTest {

  private static final String COUNT_KEY
    = DumpLoopTest.class.getName() + ".count";
  private static final int COUNT
    = Integer.getInteger(COUNT_KEY, 5);

  private static final String READ_TIMEOUT_KEY
    = DumpLoopTest.class.getName() + ".readTimeOut";
  private static final int READ_TIMEOUT
    = Integer.getInteger(READ_TIMEOUT_KEY, 5); // [ms]

  private static final String MAX_PACKT_SIZE_KEY
    = DumpLoopTest.class.getName() + ".maxPacketSize";
  private static final int MAX_PACKT_SIZE
    = Integer.getInteger(MAX_PACKT_SIZE_KEY, 65536); // [bytes]

  private static final String PCAP_FILE_KEY
    = DumpLoopTest.class.getName() + ".pcapFile";
  private static final String PCAP_FILE
    = System.getProperty(PCAP_FILE_KEY, "DumpLoopTest.pcap");

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

    final PcapHandle handle
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

    PcapDumper dumper = handle.dumpOpen(PCAP_FILE);
    try {
      handle.loop(COUNT, dumper);
    } catch (InterruptedException e) {
      e.printStackTrace();
    }

    dumper.close();
    handle.close();
  }

}
