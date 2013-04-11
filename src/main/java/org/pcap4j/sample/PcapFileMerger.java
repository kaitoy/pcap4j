package org.pcap4j.sample;

import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;

public class PcapFileMerger {

  public static void main(String[] args) throws PcapNativeException {
    // args: pcap file list

    PcapDumper dumper = null;
    for (String pcapFile: args) {
      PcapHandle handle = Pcaps.openOffline(pcapFile);

      if (dumper == null) {
        dumper = handle.dumpOpen(PcapFileMerger.class.getSimpleName() + ".pcap");
      }

      Packet packet;
      while ((packet = handle.getNextPacket()) != null) {
        dumper.dump(
          packet, handle.getTimestampInts(), handle.getTimestampMicros()
        );
      }

      handle.close();
    }

    if (dumper != null) {
      dumper.close();
    }

  }

}
