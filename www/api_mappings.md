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
    <td>int pcap_lookupnet(char *, bpf_u_int32 *, bpf_u_int32 *, char *)</td>
    <td>static Inet4NetworkAddress org.pcap4j.core.Pcaps.lookupNet(String)</td>
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
    <td>pcap_t *pcap_open_dead_with_tstamp_precision(int, int, u_int)</td>
    <td>static PcapHandle org.pcap4j.core.Pcaps.openDead(DataLinkType, int, TimestampPrecision)</td>
  </tr>
  <tr>
    <td>pcap_t *pcap_open_offline(const char *, char *)</td>
    <td>static PcapHandle org.pcap4j.core.Pcaps.openOffline(String)</td>
  </tr>
  <tr>
    <td>pcap_t *pcap_open_offline_with_tstamp_precision(const char *, u_int, char *)</td>
    <td>static PcapHandle org.pcap4j.core.Pcaps.openOffline(String, TimestampPrecision)</td>
  </tr>
  <tr>
    <td>int pcap_setnonblock(pcap_t *, int, char *)</td>
    <td>void org.pcap4j.core.PcapHandle.setBlockingMode(BlockingMode)</td>
  </tr>
  <tr>
    <td>int pcap_getnonblock(pcap_t *, char *)</td>
    <td>BlockingMode org.pcap4j.core.PcapHandle.getBlockingMode()</td>
  </tr>
  <tr>
    <td>pcap_dumper_t *pcap_dump_open(pcap_t *, const char *)</td>
    <td>PcapDumper org.pcap4j.core.PcapHandle.dumpOpen(String)</td>
  </tr>
  <tr>
    <td rowspan="4">void pcap_dump(u_char *, const struct pcap_pkthdr *, const u_char *)</td>
    <td>void org.pcap4j.core.PcapDumper.dump(Packet, TimestampPrecision)</td>
  </tr>
  <tr>
    <td>void org.pcap4j.core.PcapDumper.dump(Packet)</td>
  </tr>
  <tr>
    <td>void org.pcap4j.core.PcapDumper.dumpRaw(byte[])</td>
  </tr>
  <tr>
    <td>void org.pcap4j.core.PcapDumper.dumpRaw(byte[], TimestampPrecision)</td>
  </tr>
  <tr>
    <td>int pcap_dump_flush(pcap_dumper_t *)</td>
    <td>void org.pcap4j.core.PcapDumper.flush()</td>
  </tr>
  <tr>
    <td>long pcap_dump_ftell(pcap_dumper_t *)</td>
    <td>long org.pcap4j.core.PcapDumper.ftell()</td>
  </tr>
  <tr>
    <td>void pcap_dump_close(pcap_dumper_t *)</td>
    <td>void org.pcap4j.core.PcapDumper.close()</td>
  </tr>
  <tr>
    <td rowspan="2">u_char *pcap_next(pcap_t *, struct pcap_pkthdr *)</td>
    <td>Packet org.pcap4j.core.PcapHandle.getNextPacket()</td>
  </tr>
  <tr>
    <td>byte[] org.pcap4j.core.PcapHandle.getNextRawPacket()</td>
  </tr>
  <tr>
    <td rowspan="2">int pcap_next_ex(pcap_t *, struct pcap_pkthdr **, const u_char **)</td>
    <td>Packet org.pcap4j.core.PcapHandle.getNextPacketEx()</td>
  </tr>
  <tr>
    <td>byte[] org.pcap4j.core.PcapHandle.getNextRawPacketEx()</td>
  </tr>
  <tr>
    <td rowspan="5">int pcap_loop(pcap_t *, int, pcap_handler, u_char *)</td>
    <td>void org.pcap4j.core.PcapHandle.loop(int, PacketListener)</td>
  </tr>
  <tr>
    <td>void org.pcap4j.core.PcapHandle.loop(int, PacketListener, Executor)</td>
  </tr>
  <tr>
    <td>void org.pcap4j.core.PcapHandle.loop(int, RawPacketListener)</td>
  </tr>
  <tr>
    <td>void org.pcap4j.core.PcapHandle.loop(int, RawPacketListener, Executor)</td>
  </tr>
  <tr>
    <td>void org.pcap4j.core.PcapHandle.loop(int, PcapDumper)</td>
  </tr>
  <tr>
    <td>void pcap_breakloop(pcap_t *)</td>
    <td>void org.pcap4j.core.PcapHandle.breakLoop()</td>
  </tr>
  <tr>
    <td rowspan="4">int pcap_dispatch(pcap_t *, int, pcap_handler, u_char *)</td>
    <td>int org.pcap4j.core.PcapHandle.dispatch(int, PacketListener)</td>
  </tr>
  <tr>
    <td>int org.pcap4j.core.PcapHandle.dispatch(int, PacketListener, Executor)</td>
  </tr>
  <tr>
    <td>int org.pcap4j.core.PcapHandle.dispatch(int, RawPacketListener)</td>
  </tr>
  <tr>
    <td>int org.pcap4j.core.PcapHandle.dispatch(int, RawPacketListener, Executor)</td>
  </tr>
  <tr>
    <td>int pcap_compile(pcap_t *, struct bpf_program *, char *, int, bpf_u_int32)</td>
    <td>BpfProgram org.pcap4j.core.PcapHandle.compileFilter(String, BpfCompileMode, Inet4Address)</td>
  </tr>
  <tr>
    <td>int pcap_compile_nopcap(int, int, struct bpf_program *, char *, int, bpf_u_int32)</td>
    <td>BpfProgram org.pcap4j.core.Pcaps.compileFilter(int, DataLinkType, String, BpfCompileMode, Inet4Address)</td>
  </tr>
  <tr>
    <td rowspan="3">u_int bpf_filter(const struct bpf_insn *, const u_char *, u_int, u_int)</td>
    <td>void org.pcap4j.core.BpfProgram.applyFilter(Packet)</td>
  </tr>
  <tr>
    <td>void org.pcap4j.core.BpfProgram.applyFilter(byte[])</td>
  </tr>
  <tr>
    <td>void org.pcap4j.core.BpfProgram.applyFilter(byte[], int, int)</td>
  </tr>
  <tr>
    <td rowspan="3">int pcap_setfilter(pcap_t *, struct bpf_program *)</td>
    <td>void org.pcap4j.core.PcapHandle.setFilter(String, BpfCompileMode, Inet4Address)</td>
  </tr>
  <tr>
    <td>void org.pcap4j.core.PcapHandle.setFilter(String, BpfCompileMode)</td>
  </tr>
  <tr>
    <td>void org.pcap4j.core.PcapHandle.setFilter(BpfProgram)</td>
  </tr>
  <tr>
    <td>void pcap_freecode(struct bpf_program *)</td>
    <td>void org.pcap4j.core.BpfProgram.free()</td>
  </tr>
  <tr>
    <td rowspan="3">int pcap_sendpacket(pcap_t *, const u_char *, int)</td>
    <td>void org.pcap4j.core.PcapHandle.sendPacket(Packet)</td>
  </tr>
  <tr>
    <td>void org.pcap4j.core.PcapHandle.sendPacket(byte[])</td>
  </tr>
  <tr>
    <td>void org.pcap4j.core.PcapHandle.sendPacket(byte[], int)</td>
  </tr>
  <tr>
    <td>void pcap_close(pcap_t *)</td>
    <td>void org.pcap4j.core.PcapHandle.close()</td>
  </tr>
  <tr>
    <td>int pcap_datalink(pcap_t *)</td>
    <td>DataLinkType org.pcap4j.core.PcapHandle.getDlt()</td>
  </tr>
  <tr>
    <td>int pcap_list_datalinks(pcap_t *, int **)</td>
    <td>List<DataLinkType> org.pcap4j.core.PcapHandle.listDatalinks()</td>
  </tr>
  <tr>
    <td>void pcap_free_datalinks(int *)</td>
    <td>private mapping only</td>
  </tr>
  <tr>
    <td>int pcap_set_datalink(pcap_t *, int)</td>
    <td>void org.pcap4j.core.PcapHandle.setDlt(DataLinkType)</td>
  </tr>
  <tr>
    <td>int pcap_datalink_name_to_val(const char *)</td>
    <td>DataLinkType org.pcap4j.core.Pcaps.dataLinkNameToVal(String)</td>
  </tr>
  <tr>
    <td rowspan="2">const char* pcap_datalink_val_to_name(int)</td>
    <td>String org.pcap4j.core.Pcaps.dataLinkTypeToName(DataLinkType)</td>
  </tr>
  <tr>
    <td>String org.pcap4j.core.Pcaps.dataLinkValToName(int)</td>
  </tr>
  <tr>
    <td rowspan="2">const char* pcap_datalink_val_to_description(int)</td>
    <td>String org.pcap4j.core.Pcaps.dataLinkTypeToDescription(DataLinkType)</td>
  </tr>
  <tr>
    <td>String org.pcap4j.core.Pcaps.dataLinkValToDescription(int)</td>
  </tr>
  <tr>
    <td>int pcap_snapshot(pcap_t *)</td>
    <td>int org.pcap4j.core.PcapHandle.getSnapshot()</td>
  </tr>
  <tr>
    <td>int pcap_is_swapped(pcap_t *)</td>
    <td>SwappedType org.pcap4j.core.PcapHandle.isSwapped()</td>
  </tr>
  <tr>
    <td>int pcap_major_version(pcap_t *)</td>
    <td>int org.pcap4j.core.PcapHandle.getMajorVersion()</td>
  </tr>
  <tr>
    <td>int pcap_minor_version(pcap_t *)</td>
    <td>int org.pcap4j.core.PcapHandle.getMinorVersion()</td>
  </tr>
  <tr>
    <td>int pcap_stats(pcap_t *, struct pcap_stat *)</td>
    <td>PcapStat org.pcap4j.core.PcapHandle.getStats()</td>
  </tr>
  <tr>
    <td>struct pcap_stat* pcap_stats_ex(pcap_t *, int *) (WinPcap only)</td>
    <td>PcapStat org.pcap4j.core.PcapHandle.getStats()</td>
  </tr>
  <tr>
    <td>char *pcap_geterr(pcap_t *)</td>
    <td>String org.pcap4j.core.PcapHandle.getError()</td>
  </tr>
  <tr>
    <td>char *pcap_strerror(int)</td>
    <td>String org.pcap4j.core.Pcaps.strError(int)</td>
  </tr>
  <tr>
    <td>const char * pcap_lib_version(void)</td>
    <td>String org.pcap4j.core.Pcaps.libVersion()</td>
  </tr>
  <tr>
    <td>pcap_t *pcap_create(const char *, char *)</td>
    <td>Internally used by org.pcap4j.core.PcapHandle.Builder</td>
  </tr>
  <tr>
    <td>int pcap_set_snaplen(pcap_t *, int)</td>
    <td>Internally used by org.pcap4j.core.PcapHandle.Builder</td>
  </tr>
  <tr>
    <td>int pcap_set_promisc(pcap_t *, int)</td>
    <td>Internally used by org.pcap4j.core.PcapHandle.Builder</td>
  </tr>
  <tr>
    <td>int pcap_set_rfmon(pcap_t *, int)</td>
    <td>Internally used by org.pcap4j.core.PcapHandle.Builder</td>
  </tr>
  <tr>
    <td>int pcap_set_timeout(pcap_t *, int)</td>
    <td>Internally used by org.pcap4j.core.PcapHandle.Builder</td>
  </tr>
  <tr>
    <td>int pcap_set_buffer_size(pcap_t *, int)</td>
    <td>Internally used by org.pcap4j.core.PcapHandle.Builder</td>
  </tr>
  <tr>
    <td>int pcap_set_tstamp_precision(pcap_t*, int)</td>
    <td>Internally used by org.pcap4j.core.PcapHandle.Builder</td>
  </tr>
  <tr>
    <td rowspan="2">int pcap_setdirection(pcap_t *, pcap_direction_t)</td>
    <td>Internally used by org.pcap4j.core.PcapHandle.Builder</td>
  </tr>
  <tr>
    <td>void org.pcap4j.core.PcapHandle.setDirection(PcapDirection)</td>
  </tr>
  <tr>
    <td>int pcap_activate(pcap_t *)</td>
    <td>Internally used by org.pcap4j.core.PcapHandle.Builder</td>
  </tr>
</table>
