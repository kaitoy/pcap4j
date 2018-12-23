package org.pcap4j.core;

import static org.junit.Assert.*;

import org.junit.Test;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.packet.Packet;

@SuppressWarnings("javadoc")
public class BpfProgramTest {

  @Test
  public void testOpenLive() throws Exception {
    PcapHandle ph = Pcaps.openOffline("src/test/resources/org/pcap4j/core/udp_tcp_icmp.pcap");
    BpfProgram prog =
        ph.compileFilter("icmp", BpfCompileMode.OPTIMIZE, PcapHandle.PCAP_NETMASK_UNKNOWN);

    Packet udp = ph.getNextPacket();
    assertFalse(prog.applyFilter(udp));

    Packet tcp = ph.getNextPacket();
    assertFalse(prog.applyFilter(tcp.getRawData()));

    byte[] icmp = ph.getNextPacket().getRawData();
    byte[] icmpArr = new byte[icmp.length + 20];
    System.arraycopy(icmp, 0, icmpArr, 0, icmp.length);
    assertTrue(prog.applyFilter(icmpArr, icmp.length, icmp.length));
  }
}
