package org.pcap4j.sample;

import com.sun.jna.Platform;
import java.io.IOException;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapHandle.TimestampPrecision;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.PcapStat;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.NifSelector;

@SuppressWarnings("javadoc")
public class GetNextPacket {

  private static final String COUNT_KEY = GetNextPacket.class.getName() + ".count";
  private static final int COUNT = Integer.getInteger(COUNT_KEY, 5);

  private static final String READ_TIMEOUT_KEY = GetNextPacket.class.getName() + ".readTimeout";
  private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]

  private static final String SNAPLEN_KEY = GetNextPacket.class.getName() + ".snaplen";
  private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]

  private static final String BUFFER_SIZE_KEY = GetNextPacket.class.getName() + ".bufferSize";
  private static final int BUFFER_SIZE =
      Integer.getInteger(BUFFER_SIZE_KEY, 1 * 1024 * 1024); // [bytes]

  private static final String TIMESTAMP_PRECISION_NANO_KEY =
      GetNextPacket.class.getName() + ".timestampPrecision.nano";
  private static final boolean TIMESTAMP_PRECISION_NANO =
      Boolean.getBoolean(TIMESTAMP_PRECISION_NANO_KEY);

  private static final String NIF_NAME_KEY = GetNextPacket.class.getName() + ".nifName";
  private static final String NIF_NAME = System.getProperty(NIF_NAME_KEY);

  private GetNextPacket() {}

  public static void main(String[] args) throws PcapNativeException, NotOpenException {
    String filter = args.length != 0 ? args[0] : "";

    System.out.println(COUNT_KEY + ": " + COUNT);
    System.out.println(READ_TIMEOUT_KEY + ": " + READ_TIMEOUT);
    System.out.println(SNAPLEN_KEY + ": " + SNAPLEN);
    System.out.println(BUFFER_SIZE_KEY + ": " + BUFFER_SIZE);
    System.out.println(TIMESTAMP_PRECISION_NANO_KEY + ": " + TIMESTAMP_PRECISION_NANO);
    System.out.println(NIF_NAME_KEY + ": " + NIF_NAME);
    System.out.println("\n");

    PcapNetworkInterface nif;
    if (NIF_NAME != null) {
      nif = Pcaps.getDevByName(NIF_NAME);
    } else {
      try {
        nif = new NifSelector().selectNetworkInterface();
      } catch (IOException e) {
        e.printStackTrace();
        return;
      }

      if (nif == null) {
        return;
      }
    }

    System.out.println(nif.getName() + " (" + nif.getDescription() + ")");
    for (PcapAddress addr : nif.getAddresses()) {
      if (addr.getAddress() != null) {
        System.out.println("IP address: " + addr.getAddress());
      }
    }
    System.out.println("");

    PcapHandle.Builder phb =
        new PcapHandle.Builder(nif.getName())
            .snaplen(SNAPLEN)
            .promiscuousMode(PromiscuousMode.PROMISCUOUS)
            .timeoutMillis(READ_TIMEOUT)
            .bufferSize(BUFFER_SIZE);
    if (TIMESTAMP_PRECISION_NANO) {
      phb.timestampPrecision(TimestampPrecision.NANO);
    }
    PcapHandle handle = phb.build();

    handle.setFilter(filter, BpfCompileMode.OPTIMIZE);

    int num = 0;
    while (true) {
      Packet packet = handle.getNextPacket();
      if (packet == null) {
        continue;
      } else {
        System.out.println(handle.getTimestamp());
        System.out.println(packet);
        num++;
        if (num >= COUNT) {
          break;
        }
      }
    }

    PcapStat ps = handle.getStats();
    System.out.println("ps_recv: " + ps.getNumPacketsReceived());
    System.out.println("ps_drop: " + ps.getNumPacketsDropped());
    System.out.println("ps_ifdrop: " + ps.getNumPacketsDroppedByIf());
    if (Platform.isWindows()) {
      System.out.println("bs_capt: " + ps.getNumPacketsCaptured());
    }

    handle.close();
  }
}
