package org.pcap4j.sample;

import java.io.EOFException;
import java.sql.Timestamp;
import java.util.concurrent.TimeoutException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;

public class ReadPacketFile {

  private static final int COUNT = 5;

  private static final String PCAP_FILE_KEY
    = ReadPacketFile.class.getName() + ".pcapFile";
  private static final String PCAP_FILE
    = System.getProperty(PCAP_FILE_KEY, "src/main/resources/echoAndEchoReply.pcap");

  public static void main(String[] args) throws PcapNativeException {
    PcapHandle handle = Pcaps.openOffline(PCAP_FILE);

    for (int i = 0; i < COUNT; i++) {
      try {
        Packet packet = handle.getNextPacketEx();
        Timestamp ts = new Timestamp(handle.getTimestampInts() * 1000L);
        ts.setNanos(handle.getTimestampMicros() * 1000);

        System.out.println(ts);
        System.out.println(packet);
      } catch (TimeoutException e) {
      } catch (EOFException e) {
        System.out.println("EOF");
        break;
      }
    }

    handle.close();
  }

}
