package org.pcap4j.sample;

import java.io.EOFException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeoutException;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.SimpleBuilder;
import org.pcap4j.util.IpV4Helper;

@SuppressWarnings("javadoc")
public class DefragmentEcho {

  private static final String PCAP_FILE_KEY = DefragmentEcho.class.getName() + ".pcapFile";
  private static final String PCAP_FILE =
      System.getProperty(PCAP_FILE_KEY, "src/main/resources/flagmentedEcho.pcap");

  private DefragmentEcho() {}

  public static void main(String[] args) throws PcapNativeException, NotOpenException {
    PcapHandle handle = Pcaps.openOffline(PCAP_FILE);

    Map<Short, List<IpV4Packet>> ipV4Packets = new HashMap<Short, List<IpV4Packet>>();
    Map<Short, Packet> originalPackets = new HashMap<Short, Packet>();

    while (true) {
      try {
        Packet packet = handle.getNextPacketEx();
        Short id = packet.get(IpV4Packet.class).getHeader().getIdentification();
        if (ipV4Packets.containsKey(id)) {
          ipV4Packets.get(id).add(packet.get(IpV4Packet.class));
        } else {
          List<IpV4Packet> list = new ArrayList<IpV4Packet>();
          list.add(packet.get(IpV4Packet.class));
          ipV4Packets.put(id, list);
          originalPackets.put(id, packet);
        }
      } catch (TimeoutException e) {
        continue;
      } catch (EOFException e) {
        break;
      }
    }

    for (Short id : ipV4Packets.keySet()) {
      List<IpV4Packet> list = ipV4Packets.get(id);
      final IpV4Packet defragmentedIpV4Packet = IpV4Helper.defragment(list);

      Packet.Builder builder = originalPackets.get(id).getBuilder();
      builder
          .getOuterOf(IpV4Packet.Builder.class)
          .payloadBuilder(new SimpleBuilder(defragmentedIpV4Packet));

      System.out.println(builder.build());
    }

    handle.close();
  }
}
