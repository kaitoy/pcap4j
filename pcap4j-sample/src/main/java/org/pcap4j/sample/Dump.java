package org.pcap4j.sample;

import java.io.IOException;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.NifSelector;

public class Dump {

  private static final String COUNT_KEY
    = Dump.class.getName() + ".count";
  private static final int COUNT
    = Integer.getInteger(COUNT_KEY, 5);

  private static final String READ_TIMEOUT_KEY
    = Dump.class.getName() + ".readTimeout";
  private static final int READ_TIMEOUT
    = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]

  private static final String MAX_CAP_LEN_KEY
    = Dump.class.getName() + ".maxCapLen";
  private static final int MAX_CAP_LEN
    = Integer.getInteger(MAX_CAP_LEN_KEY, 65536); // [bytes]

  private static final String PCAP_FILE_KEY
    = Dump.class.getName() + ".pcapFile";
  private static final String PCAP_FILE
    = System.getProperty(PCAP_FILE_KEY, "Dump.pcap");

  public static void main(String[] args) throws PcapNativeException, NotOpenException {
    String filter = args.length != 0 ? args[0] : "";

    System.out.println(COUNT_KEY + ": " + COUNT);
    System.out.println(READ_TIMEOUT_KEY + ": " + READ_TIMEOUT);
    System.out.println(MAX_CAP_LEN_KEY + ": " + MAX_CAP_LEN);
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
      = nif.openLive(MAX_CAP_LEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);

    handle.setFilter(
      filter,
      BpfCompileMode.OPTIMIZE
    );

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
