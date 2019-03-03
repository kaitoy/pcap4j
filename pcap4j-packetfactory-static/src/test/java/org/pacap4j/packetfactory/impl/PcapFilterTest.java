package org.pacap4j.packetfactory.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.EOFException;

import org.junit.Test;
import org.pcap4j.core.BpfProgram;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UdpPacket;

public class PcapFilterTest {

    private static final String UDP_TCP_ICMP_PCAP = "src/test/resources/org/pcap4j/packetfactory/static/udp_tcp_icmp.pcap";

    @Test
    public void testSetFilterIcmp() throws Exception {
        PcapHandle handle = null;
        try {
            handle = Pcaps.openOffline(UDP_TCP_ICMP_PCAP);
            handle.setFilter("icmp", BpfCompileMode.OPTIMIZE);
            int count = 0;
            try {
                while (true) {
                    Packet p = handle.getNextPacketEx();
                    assertNotNull(p.get(IcmpV4CommonPacket.class));
                    count++;
                }
            } catch (EOFException e) {
            }
            assertEquals(1, count);
        } finally {
            if (handle != null) {
                handle.close();
            }
        }
    }

    @Test
    public void testSetFilterUdp() throws Exception {
        PcapHandle handle = null;
        BpfProgram prog = null;
        try {
            handle = Pcaps.openOffline(UDP_TCP_ICMP_PCAP);
            prog = handle.compileFilter("udp", BpfCompileMode.OPTIMIZE, PcapHandle.PCAP_NETMASK_UNKNOWN);
            handle.setFilter(prog);
            int count = 0;
            try {
                while (true) {
                    Packet p = handle.getNextPacketEx();
                    assertNotNull(p.get(UdpPacket.class));
                    count++;
                }
            } catch (EOFException e) {
            }
            assertEquals(1, count);
        } finally {
            if (handle != null) {
                handle.close();
            }
            if (prog != null) {
                prog.free();
            }
        }
    }
}
