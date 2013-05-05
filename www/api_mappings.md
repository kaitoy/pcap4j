Mapping between pcap API and Pcap4j API
=======================================

<table border="1">
  <tr align=center>
    <td>pcap API</td>
    <td>Pcap4j API</td>
  </tr>
  <tr>
    <td>int pcap_findalldevs(pcap_if_t **, char *)</td>
    <td>static List&lt;PcapNetworkInterface&gt; org.pcap4j.core.Pcaps.findAllDevs()</td>
  </tr>
  <tr>
    <td>void pcap_freealldevs(pcap_if_t *)</td>
    <td>private mapping only</td>
  </tr>
  <tr>
    <td>char *pcap_lookupdev(char *)</td>
    <td>static String org.pcap4j.core.Pcaps.lookupDev()</td>
  </tr>
  <tr>
    <td>pcap_t *pcap_open_live(const char *, int, int, int, char *)</td>
    <td>PcapHandle org.pcap4j.core.PcapNetworkInterface.openLive(int, PromiscuousMode, int)</td>
  </tr>
  <tr>
    <td>pcap_t *pcap_open_dead(int, int)</td>
    <td>static PcapHandle org.pcap4j.core.Pcaps.openDead(DataLinkType, int)</td>
  </tr>
  <tr>
    <td>pcap_t *pcap_open_offline(const char *, char *)</td>
    <td>static PcapHandle org.pcap4j.core.Pcaps.openOffline(String)</td>
  </tr>
  <tr>
    <td>pcap_dumper_t *pcap_dump_open(pcap_t *, const char *)</td>
    <td>PcapDumper org.pcap4j.core.PcapHandle.dumpOpen(String)</td>
  </tr>
  <tr>
    <td rowspan="2">void pcap_dump(u_char *, const struct pcap_pkthdr *, const u_char *)</td>
    <td>void org.pcap4j.core.PcapDumper.dump(Packet, long, int)</td>
  </tr>
  <tr>
    <td>void org.pcap4j.core.PcapDumper.dump(Packet)</td>
  </tr>
  <tr>
    <td>void pcap_dump_close(pcap_dumper_t *)</td>
    <td>void org.pcap4j.core.PcapDumper.close()</td>
  </tr>
  <tr>
    <td>u_char *pcap_next(pcap_t *, struct pcap_pkthdr *)</td>
    <td>Packet org.pcap4j.core.PcapHandle.getNextPacket()</td>
  </tr>
  <tr>
    <td>int pcap_next_ex(pcap_t *, struct pcap_pkthdr **, const u_char **)</td>
    <td>Packet org.pcap4j.core.PcapHandle.getNextPacketEx()</td>
  </tr>
  <tr>
    <td rowspan="3">int pcap_loop(pcap_t *, int, pcap_handler, u_char *)</td>
    <td>void org.pcap4j.core.PcapHandle.loop(int, PacketListener)</td>
  </tr>
  <tr>
    <td>void org.pcap4j.core.PcapHandle.loop(int, PacketListener, Executor)</td>
  </tr>
  <tr>
    <td>void org.pcap4j.core.PcapHandle.loop(int, PcapDumper)</td>
  </tr>
  <tr>
    <td>void pcap_breakloop(pcap_t *)</td>
    <td>void org.pcap4j.core.PcapHandle.breakLoop()</td>
  </tr>
  <tr>
    <td>int pcap_compile(pcap_t *, struct bpf_program *, char *, int, bpf_u_int32)</td>
    <td>private mapping only</td>
  </tr>
  <tr>
    <td rowspan="2">int pcap_setfilter(pcap_t *, struct bpf_program *)</td>
    <td>void org.pcap4j.core.PcapHandle.setFilter(String, BpfCompileMode, Inet4Address)</td>
  </tr>
  <tr>
    <td>void org.pcap4j.core.PcapHandle.setFilter(String, BpfCompileMode)</td>
  </tr>
  <tr>
    <td>void pcap_freecode(struct bpf_program *)</td>
    <td>private mapping only</td>
  </tr>
  <tr>
    <td>int pcap_sendpacket(pcap_t *, const u_char *, int)</td>
    <td>void org.pcap4j.core.PcapHandle.sendPacket(Packet)</td>
  </tr>
  <tr>
    <td>void pcap_close(pcap_t *)</td>
    <td>void org.pcap4j.core.PcapHandle.close()</td>
  </tr>
  <tr>
    <td>int pcap_datalink(pcap_t *)</td>
    <td>private mapping only</td>
  </tr>
  <tr>
    <td>char *pcap_geterr(pcap_t *)</td>
    <td>String org.pcap4j.core.PcapHandle.getError()</td>
  </tr>
  <tr>
    <td>char *pcap_strerror(int)</td>
    <td>private mapping only</td>
  </tr>
</table>
