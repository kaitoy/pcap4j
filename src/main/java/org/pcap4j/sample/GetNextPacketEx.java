package org.pcap4j.sample;

import java.io.EOFException;
import java.io.IOException;
import java.sql.Timestamp;
import java.util.concurrent.TimeoutException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapHandle.BpfCompileMode;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.NifSelector;

public class GetNextPacketEx {

  private static final String COUNT_KEY
    = GetNextPacketEx.class.getName() + ".count";
  private static final int COUNT
    = Integer.getInteger(COUNT_KEY, 5);

  private static final String READ_TIMEOUT_KEY
    = GetNextPacketEx.class.getName() + ".readTimeout";
  private static final int READ_TIMEOUT
    = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]

  private static final String MAX_CAP_LEN_KEY
    = GetNextPacketEx.class.getName() + ".maxCapLen";
  private static final int MAX_CAP_LEN
    = Integer.getInteger(MAX_CAP_LEN_KEY, 65536); // [bytes]

  public static void main(String[] args) throws PcapNativeException {
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
    while (true) {
      try {
        Packet packet = handle.getNextPacketEx();
        Timestamp ts = new Timestamp(handle.getTimestampInts() * 1000L);
        ts.setNanos(handle.getTimestampMicros() * 1000);

        System.out.println(ts);
        System.out.println(packet);
        num++;
        if (num >= COUNT) {
          break;
        }
      } catch (TimeoutException e) {
      } catch (EOFException e) {
        e.printStackTrace();
      }
    }

    handle.close();
  }

}
