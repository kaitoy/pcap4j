package org.pcap4j.sample;

import java.io.EOFException;
import java.io.IOException;
import java.util.concurrent.TimeoutException;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.NifSelector;

@SuppressWarnings("javadoc")
public class GetRawNextPacketEx {

  private static final String COUNT_KEY = GetRawNextPacketEx.class.getName() + ".count";
  private static final int COUNT = Integer.getInteger(COUNT_KEY, 5);

  private static final String READ_TIMEOUT_KEY =
      GetRawNextPacketEx.class.getName() + ".readTimeout";
  private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]

  private static final String SNAPLEN_KEY = GetRawNextPacketEx.class.getName() + ".snaplen";
  private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]

  private GetRawNextPacketEx() {}

  public static void main(String[] args) throws PcapNativeException, NotOpenException {
    String filter = args.length != 0 ? args[0] : "";

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

    handle.setFilter(filter, BpfCompileMode.OPTIMIZE);

    int num = 0;
    while (true) {
      try {
        byte[] packet = handle.getNextRawPacketEx();
        System.out.println(handle.getTimestamp());
        System.out.println(ByteArrays.toHexString(packet, " "));
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
