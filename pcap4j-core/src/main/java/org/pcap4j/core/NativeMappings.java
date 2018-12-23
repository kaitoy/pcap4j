/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2017  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.core;

import com.sun.jna.Callback;
import com.sun.jna.Function;
import com.sun.jna.FunctionMapper;
import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.NativeLibrary;
import com.sun.jna.NativeLong;
import com.sun.jna.Platform;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;
import java.lang.reflect.Method;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
final class NativeMappings {

  private static final Logger LOG = LoggerFactory.getLogger(NativeMappings.class);

  static final String PCAP_LIB_NAME =
      System.getProperty(
          NativeMappings.class.getPackage().getName() + ".pcapLibName",
          Platform.isWindows() ? "wpcap" : "pcap");

  static final Function PCAP_DUMP = Function.getFunction(PCAP_LIB_NAME, "pcap_dump");

  static final Map<String, Object> NATIVE_LOAD_LIBRARY_OPTIONS = new HashMap<String, Object>();

  // LITTLE_ENDIAN: SPARC, JVM
  // BIG_ENDIAN: x86, network bite order
  static final ByteOrder NATIVE_BYTE_ORDER = ByteOrder.nativeOrder();

  static final int SBIOCSTIME = 0x4201;

  static final Pointer ERRNO_P =
      Platform.isSolaris()
          ? NativeLibrary.getInstance(PCAP_LIB_NAME).getGlobalVariableAddress("errno")
          : null;

  // see pcap-int.h: struct pcap
  static int getFdFromPcapT(Pointer p) {
    if (Platform.isWindows()) {
      return -1;
    }
    return p.getInt(0);
  }

  static {
    Native.register(NativeMappings.class, NativeLibrary.getInstance(PCAP_LIB_NAME));

    // for interface mapping
    final Map<String, String> funcMap = new HashMap<String, String>();
    funcMap.put("pcap_set_rfmon", "pcap_set_rfmon");
    funcMap.put("strioctl", "strioctl");
    funcMap.put("dos_pcap_stats_ex", "pcap_stats_ex");
    funcMap.put("win_pcap_stats_ex", "pcap_stats_ex");
    funcMap.put(
        "pcap_open_offline_with_tstamp_precision", "pcap_open_offline_with_tstamp_precision");
    funcMap.put("pcap_open_dead_with_tstamp_precision", "pcap_open_dead_with_tstamp_precision");
    funcMap.put("pcap_set_tstamp_precision", "pcap_set_tstamp_precision");
    funcMap.put("pcap_set_immediate_mode", "pcap_set_immediate_mode");

    NATIVE_LOAD_LIBRARY_OPTIONS.put(
        Library.OPTION_FUNCTION_MAPPER,
        new FunctionMapper() {

          @Override
          public String getFunctionName(NativeLibrary library, Method method) {
            return funcMap.get(method.getName());
          }
        });

    LOG.info("Pcap4J successfully loaded a native pcap library: {}", pcap_lib_version());
  }

  // direct mappings

  // int pcap_findalldevs(pcap_if_t **alldevsp, char *errbuf)
  static native int pcap_findalldevs(PointerByReference alldevsp, PcapErrbuf errbuf);

  // TODO WinPcap: int pcap_findalldevs_ex(char *host, char *port, SOCKET sockctrl, struct
  // pcap_rmtauth *auth, pcap_if_t **alldevs, char *errbuf)

  // void  pcap_freealldevs (pcap_if_t *alldevsp)
  static native void pcap_freealldevs(Pointer alldevsp);

  // char *pcap_lookupdev(char *errbuf)
  static native Pointer pcap_lookupdev(PcapErrbuf errbuf);

  // int pcap_lookupnet(char *device, bpf_u_int32 *netp, bpf_u_int32 *maskp, char *errbuf)
  static native int pcap_lookupnet(
      String device, IntByReference netp, IntByReference maskp, PcapErrbuf errbuf);

  // pcap_t *pcap_open_live(
  //   const char *device, int snaplen, int promisc, int to_ms, char *errbuf
  // )
  static native Pointer pcap_open_live(
      String device, int snaplen, int promisc, int to_ms, PcapErrbuf errbuf);

  // pcap_t *pcap_open_dead (int linktype, int snaplen)
  static native Pointer pcap_open_dead(int linktype, int snaplen);

  // pcap_t *pcap_open_offline(const char *fname, char *errbuf)
  static native Pointer pcap_open_offline(String fname, PcapErrbuf errbuf);

  // TODO WinPcap: pcap_t *pcap_open(const char *source, int snaplen, int flags, int read_timeout,
  // struct pcap_rmtauth *auth, char *errbuf)

  // int pcap_setnonblock(pcap_t *p, int nonblock, char *errbuf)
  static native int pcap_setnonblock(Pointer p, int nonblock, PcapErrbuf errbuf);

  // int pcap_getnonblock(pcap_t *p, char *errbuf)
  static native int pcap_getnonblock(Pointer p, PcapErrbuf errbuf);

  // pcap_dumper_t *pcap_dump_open(pcap_t *p, const char *fname)
  static native Pointer pcap_dump_open(Pointer p, String fname);

  // void pcap_dump(u_char *user, const struct pcap_pkthdr *h, const u_char *sp)
  static native void pcap_dump(Pointer user, pcap_pkthdr header, byte[] packet);

  // int pcap_dump_flush(pcap_dumper_t *p)
  static native int pcap_dump_flush(Pointer p);

  // long pcap_dump_ftell(pcap_dumper_t *)
  static native NativeLong pcap_dump_ftell(Pointer dumper);

  // void pcap_dump_close(pcap_dumper_t *p)
  static native void pcap_dump_close(Pointer p);

  // TODO WinPcap: int pcap_live_dump(pcap_t *p, char *filename, int maxsize, int maxpacks)

  // int pcap_dispatch(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
  static native int pcap_dispatch(Pointer p, int cnt, pcap_handler callback, Pointer user);

  // u_char *pcap_next(pcap_t *p, struct pcap_pkthdr *h)
  static native Pointer pcap_next(Pointer p, pcap_pkthdr h);

  // int pcap_next_ex(pcap_t *p, struct pcap_pkthdr **h, const u_char **data)
  static native int pcap_next_ex(Pointer p, PointerByReference h, PointerByReference data);

  // int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
  static native int pcap_loop(Pointer p, int cnt, pcap_handler callback, Pointer user);

  static native int pcap_loop(Pointer p, int cnt, Function callback, Pointer user);

  // void pcap_breakloop(pcap_t *p)
  static native void pcap_breakloop(Pointer p);

  // int pcap_compile(
  //   pcap_t *p, struct bpf_program *fp, char *str,
  //   int optimize, bpf_u_int32 netmask
  // )
  static native int pcap_compile(Pointer p, bpf_program fp, String str, int optimize, int netmask);

  // int pcap_compile_nopcap(
  //   int snaplen_arg, int linktype_arg, struct bpf_program *program, char *buf,
  //   int optimize, bpf_u_int32 mask
  // )
  static native int pcap_compile_nopcap(
      int snaplen_arg, int linktype_arg, bpf_program fp, String buf, int optimize, int mask);

  // u_int bpf_filter(const struct bpf_insn *, const u_char *, u_int, u_int)
  static native int bpf_filter(
      bpf_insn.ByReference bpf_insn, byte[] packet, int wirelen, int buflen);

  // int pcap_setfilter(pcap_t *p, struct bpf_program *fp)
  static native int pcap_setfilter(Pointer p, bpf_program fp);

  // void pcap_freecode(struct bpf_program *fp)
  static native void pcap_freecode(bpf_program fp);

  // int pcap_sendpacket(pcap_t *p, const u_char *buf, int size)
  static native int pcap_sendpacket(Pointer p, byte[] buf, int size);

  // void pcap_close(pcap_t *p)
  static native void pcap_close(Pointer p);

  // int pcap_datalink(pcap_t *p)
  static native int pcap_datalink(Pointer p);

  // int pcap_list_datalinks(pcap_t *p, int **dlt_buf)
  static native int pcap_list_datalinks(Pointer p, PointerByReference dlt_buf);

  // void pcap_free_datalinks(int *dlt_list)
  static native void pcap_free_datalinks(Pointer dlt_list);

  // int pcap_set_datalink(pcap_t *p, int dlt)
  static native int pcap_set_datalink(Pointer p, int dlt);

  // int pcap_datalink_name_to_val(const char *name)
  static native int pcap_datalink_name_to_val(String name);

  // const char * pcap_datalink_val_to_name(int dlt)
  static native String pcap_datalink_val_to_name(int dlt);

  // const char* pcap_datalink_val_to_description(int dlt)
  static native String pcap_datalink_val_to_description(int dlt);

  // int pcap_snapshot(pcap_t *p)
  static native int pcap_snapshot(Pointer p);

  // int pcap_is_swapped(pcap_t *p)
  static native int pcap_is_swapped(Pointer p);

  // int pcap_major_version(pcap_t *p)
  static native int pcap_major_version(Pointer p);

  // int pcap_minor_version(pcap_t *p)
  static native int pcap_minor_version(Pointer p);

  // int pcap_stats(pcap_t *p, struct pcap_stat *ps)
  static native int pcap_stats(Pointer p, pcap_stat ps);

  // char *pcap_geterr(pcap_t *p)
  static native Pointer pcap_geterr(Pointer p);

  // char *pcap_strerror(int errno)
  static native Pointer pcap_strerror(int errno);

  // const char * pcap_lib_version(void)
  static native String pcap_lib_version();

  // pcap_t *pcap_create (const char *device, char *ebuf)
  static native Pointer pcap_create(String device, PcapErrbuf ebuf);

  // int pcap_set_snaplen(pcap_t *p, int snaplen)
  static native int pcap_set_snaplen(Pointer p, int snaplen);

  // int pcap_set_promisc(pcap_t *p, int promisc)
  static native int pcap_set_promisc(Pointer p, int promisc);

  // int pcap_set_timeout(pcap_t *p, int timeout_ms)
  static native int pcap_set_timeout(Pointer p, int timeout_ms);

  // int pcap_set_buffer_size(pcap_t *p, int buffer_size)
  static native int pcap_set_buffer_size(Pointer p, int buffer_size);

  // int pcap_setdirection(pcap_t *, pcap_direction_t)
  static native int pcap_setdirection(Pointer p, int pcap_direction);

  // int pcap_activate(pcap_t *p)
  static native int pcap_activate(Pointer p);

  // interface mappings
  interface PcapLibrary extends Library {

    static final PcapLibrary INSTANCE =
        (PcapLibrary) Native.load(PCAP_LIB_NAME, PcapLibrary.class, NATIVE_LOAD_LIBRARY_OPTIONS);

    // The following functions can't be mapped directly because they are supported by not all
    // OSes
    // or by only very new versions of pcap libraries.
    // If you add a method here you need to put the method to funcMap in static initialization
    // block above.

    // int pcap_set_rfmon(pcap_t *p, int rfmon)
    int pcap_set_rfmon(Pointer p, int rfmon);

    // int strioctl(int fd, int cmd, int len, char *dp)
    int strioctl(int fd, int cmd, int len, Pointer dp);

    // int pcap_stats_ex(pcap_t *p, struct pcap_stat_ex *ps)
    int dos_pcap_stats_ex(Pointer p, pcap_stat_ex ps);

    // struct pcap_stat* pcap_stats_ex(pcap_t *p, int *pcap_stat_size)
    Pointer win_pcap_stats_ex(Pointer p, IntByReference pcap_stat_size);

    // pcap_t *pcap_open_offline_with_tstamp_precision(const char *fname, u_int precision,
    // char*errbuf);
    Pointer pcap_open_offline_with_tstamp_precision(String fname, int precision, PcapErrbuf errbuf);

    // pcap_t *pcap_open_dead_with_tstamp_precision(int linktype, int snaplen, u_int precision);
    Pointer pcap_open_dead_with_tstamp_precision(int linkType, int snaplen, int precision);

    // int pcap_set_tstamp_precision(pcap_t *p, int tstamp_precision)
    int pcap_set_tstamp_precision(Pointer p, int tstamp_precision);

    // int pcap_set_immediate_mode(pcap_t *p, int immediate_mode)
    int pcap_set_immediate_mode(Pointer p, int immediate_mode);
  }

  static interface pcap_handler extends Callback {

    // void got_packet(
    //   u_char *args, const struct pcap_pkthdr *header, const u_char *packet
    // );
    public void got_packet(Pointer args, Pointer header, Pointer packet);
  }

  public static class pcap_if extends Structure {

    public pcap_if.ByReference next; // struct pcap_if *
    public String name; // char *
    public String description; // char *
    public pcap_addr.ByReference addresses; // struct pcap_addr *
    public int flags; // bpf_u_int32

    public pcap_if() {}

    public pcap_if(Pointer p) {
      super(p);
      read();
    }

    public static class ByReference extends pcap_if implements Structure.ByReference {}

    @Override
    protected List<String> getFieldOrder() {
      List<String> list = new ArrayList<String>();
      list.add("next");
      list.add("name");
      list.add("description");
      list.add("addresses");
      list.add("flags");
      return list;
    }
  }

  public static class pcap_addr extends Structure {

    public pcap_addr.ByReference next; // struct pcap_addr *
    public sockaddr.ByReference addr; // struct sockaddr *
    public sockaddr.ByReference netmask; // struct sockaddr *
    public sockaddr.ByReference broadaddr; // struct sockaddr *
    public sockaddr.ByReference dstaddr; // struct sockaddr *

    public pcap_addr() {}

    public pcap_addr(Pointer p) {
      super(p);
      read();
    }

    public static class ByReference extends pcap_addr implements Structure.ByReference {}

    @Override
    protected List<String> getFieldOrder() {
      List<String> list = new ArrayList<String>();
      list.add("next");
      list.add("addr");
      list.add("netmask");
      list.add("broadaddr");
      list.add("dstaddr");
      return list;
    }
  }

  public static class sockaddr extends Structure {

    public short sa_family; // u_short
    public byte[] sa_data = new byte[14]; // char[14]

    public sockaddr() {}

    public sockaddr(Pointer p) {
      super(p);
      read();
    }

    public static class ByReference extends sockaddr implements Structure.ByReference {}

    @Override
    protected List<String> getFieldOrder() {
      List<String> list = new ArrayList<String>();
      list.add("sa_family");
      list.add("sa_data");
      return list;
    }

    short getSaFamily() {
      if (isWindowsType()) {
        return sa_family;
      } else {
        if (NATIVE_BYTE_ORDER.equals(ByteOrder.BIG_ENDIAN)) {
          return (short) (0xFF & sa_family);
        } else {
          return (short) (0xFF & (sa_family >> 8));
        }
      }
    }

    static boolean isWindowsType() {
      if (Platform.isMac()
          || Platform.isFreeBSD()
          || Platform.isOpenBSD()
          || Platform.iskFreeBSD()) {
        return false;
      } else {
        return true;
      }
    }
  }

  public static class sockaddr_in extends Structure {

    public short sin_family; // short
    public short sin_port; // u_short
    public in_addr sin_addr; // struct in_addr
    public byte[] sin_zero = new byte[8]; // char[8]

    public sockaddr_in() {}

    public sockaddr_in(Pointer p) {
      super(p);
      read();
    }

    @Override
    protected List<String> getFieldOrder() {
      List<String> list = new ArrayList<String>();
      list.add("sin_family");
      list.add("sin_port");
      list.add("sin_addr");
      list.add("sin_zero");
      return list;
    }

    short getSaFamily() {
      if (sockaddr.isWindowsType()) {
        return sin_family;
      } else {
        if (NATIVE_BYTE_ORDER.equals(ByteOrder.BIG_ENDIAN)) {
          return (short) (0xFF & sin_family);
        } else {
          return (short) (0xFF & (sin_family >> 8));
        }
      }
    }
  }

  public static class in_addr extends Structure {

    public int s_addr; // in_addr_t = uint32_t

    public in_addr() {}

    @Override
    protected List<String> getFieldOrder() {
      List<String> list = new ArrayList<String>();
      list.add("s_addr");
      return list;
    }
  }

  public static class sockaddr_in6 extends Structure {

    public short sin6_family; // u_int16_t
    public short sin6_port; // u_int16_t
    public int sin6_flowinfo; // u_int32_t
    public in6_addr sin6_addr; // struct in6_addr
    public int sin6_scope_id; // u_int32_t

    public sockaddr_in6() {}

    public sockaddr_in6(Pointer p) {
      super(p);
      read();
    }

    @Override
    protected List<String> getFieldOrder() {
      List<String> list = new ArrayList<String>();
      list.add("sin6_family");
      list.add("sin6_port");
      list.add("sin6_flowinfo");
      list.add("sin6_addr");
      list.add("sin6_scope_id");
      return list;
    }

    short getSaFamily() {
      if (sockaddr.isWindowsType()) {
        return sin6_family;
      } else {
        if (NATIVE_BYTE_ORDER.equals(ByteOrder.BIG_ENDIAN)) {
          return (short) (0xFF & sin6_family);
        } else {
          return (short) (0xFF & (sin6_family >> 8));
        }
      }
    }
  }

  public static class in6_addr extends Structure {

    public byte[] s6_addr = new byte[16]; // unsigned char[16]

    public in6_addr() {}

    @Override
    protected List<String> getFieldOrder() {
      List<String> list = new ArrayList<String>();
      list.add("s6_addr");
      return list;
    }
  }

  // Linux specific
  public static class sockaddr_ll extends Structure {

    public short sll_family; // unsigned short
    public short sll_protocol; // __be16
    public int sll_ifindex; // int
    public short sll_hatype;; // unsigned short
    public byte sll_pkttype; // unsigned char
    public byte sll_halen; // unsigned char
    public byte[] sll_addr = new byte[8]; // unsigned char[8]

    public sockaddr_ll() {}

    public sockaddr_ll(Pointer p) {
      super(p);
      read();
    }

    @Override
    protected List<String> getFieldOrder() {
      List<String> list = new ArrayList<String>();
      list.add("sll_family");
      list.add("sll_protocol");
      list.add("sll_ifindex");
      list.add("sll_hatype");
      list.add("sll_pkttype");
      list.add("sll_halen");
      list.add("sll_addr");
      return list;
    }

    short getSaFamily() {
      if (sockaddr.isWindowsType()) {
        return sll_family;
      } else {
        if (NATIVE_BYTE_ORDER.equals(ByteOrder.BIG_ENDIAN)) {
          return (short) (0xFF & sll_family);
        } else {
          return (short) (0xFF & (sll_family >> 8));
        }
      }
    }
  }

  // Mac OS X and BSD specific
  public static class sockaddr_dl extends Structure {

    public byte sdl_len; // u_char
    public byte sdl_family; // u_char
    public short sdl_index; // u_short
    public byte sdl_type; // u_char
    public byte sdl_nlen;; // u_char
    public byte sdl_alen; // u_char
    public byte sdl_slen; // u_char
    public byte[] sdl_data = new byte[46]; // unsigned char[46]
    // minimum work area, can be larger;
    // contains both if name and ll address

    public sockaddr_dl() {}

    public sockaddr_dl(Pointer p) {
      super(p);
      read();
    }

    @Override
    protected List<String> getFieldOrder() {
      List<String> list = new ArrayList<String>();
      list.add("sdl_len");
      list.add("sdl_family");
      list.add("sdl_index");
      list.add("sdl_type");
      list.add("sdl_nlen");
      list.add("sdl_alen");
      list.add("sdl_slen");
      list.add("sdl_data");
      return list;
    }

    byte[] getAddress() {
      return getPointer().getByteArray(8 + (0xFF & sdl_nlen), 0xFF & sdl_alen);
    }
  }

  public static class pcap_pkthdr extends Structure {

    public static final int TS_OFFSET;
    public static final int CAPLEN_OFFSET;
    public static final int LEN_OFFSET;

    public timeval ts; // struct timeval
    public int caplen; // bpf_u_int32
    public int len; // bpf_u_int32

    static {
      pcap_pkthdr ph = new pcap_pkthdr();
      TS_OFFSET = ph.fieldOffset("ts");
      CAPLEN_OFFSET = ph.fieldOffset("caplen");
      LEN_OFFSET = ph.fieldOffset("len");
    }

    public pcap_pkthdr() {}

    public pcap_pkthdr(Pointer p) {
      super(p);
      read();
    }

    public static class ByReference extends pcap_pkthdr implements Structure.ByReference {}

    @Override
    protected List<String> getFieldOrder() {
      List<String> list = new ArrayList<String>();
      list.add("ts");
      list.add("caplen");
      list.add("len");
      return list;
    }

    static NativeLong getTvSec(Pointer p) {
      return p.getNativeLong(TS_OFFSET + timeval.TV_SEC_OFFSET);
    }

    static NativeLong getTvUsec(Pointer p) {
      return p.getNativeLong(TS_OFFSET + timeval.TV_USEC_OFFSET);
    }

    static int getCaplen(Pointer p) {
      return p.getInt(CAPLEN_OFFSET);
    }

    static int getLen(Pointer p) {
      return p.getInt(LEN_OFFSET);
    }
  }

  public static class timeval extends Structure {

    public static final int TV_SEC_OFFSET;
    public static final int TV_USEC_OFFSET;

    public NativeLong tv_sec; // long
    public NativeLong tv_usec; // long

    static {
      timeval tv = new timeval();
      TV_SEC_OFFSET = tv.fieldOffset("tv_sec");
      TV_USEC_OFFSET = tv.fieldOffset("tv_usec");
    }

    public timeval() {}

    @Override
    protected List<String> getFieldOrder() {
      List<String> list = new ArrayList<String>();
      list.add("tv_sec");
      list.add("tv_usec");
      return list;
    }
  }

  public static class bpf_program extends Structure {

    public int bf_len; // u_int
    public bpf_insn.ByReference bf_insns; // struct bpf_insn *

    public bpf_program() {
      setAutoSynch(false);
    }

    @Override
    protected List<String> getFieldOrder() {
      List<String> list = new ArrayList<String>();
      list.add("bf_len");
      list.add("bf_insns");
      return list;
    }
  }

  public static class bpf_insn extends Structure {

    public short code; // u_short
    public byte jt; // u_char
    public byte jf; // u_char
    public int k; // bpf_u_int32

    public bpf_insn() {
      setAutoSynch(false);
    }

    public static class ByReference extends bpf_insn implements Structure.ByReference {}

    @Override
    protected List<String> getFieldOrder() {
      List<String> list = new ArrayList<String>();
      list.add("code");
      list.add("jt");
      list.add("jf");
      list.add("k");
      return list;
    }
  };

  public static class pcap_stat extends Structure {

    public static final int PS_RECV_OFFSET;
    public static final int PS_DROP_OFFSET;
    public static final int PS_IFDROP_OFFSET;

    public int ps_recv; // u_int
    public int ps_drop; // u_int
    public int ps_ifdrop; // u_int

    static {
      pcap_stat ph = new pcap_stat();
      PS_RECV_OFFSET = ph.fieldOffset("ps_recv");
      PS_DROP_OFFSET = ph.fieldOffset("ps_drop");
      PS_IFDROP_OFFSET = ph.fieldOffset("ps_ifdrop");
    }

    public pcap_stat() {}

    public pcap_stat(Pointer p) {
      super(p);
      read();
    }

    public static class ByReference extends pcap_stat implements Structure.ByReference {}

    @Override
    protected List<String> getFieldOrder() {
      List<String> list = new ArrayList<String>();
      list.add("ps_recv");
      list.add("ps_drop");
      list.add("ps_ifdrop");
      return list;
    }

    static int getPsRecv(Pointer p) {
      return p.getInt(PS_RECV_OFFSET);
    }

    static int getPsDrop(Pointer p) {
      return p.getInt(PS_DROP_OFFSET);
    }

    static int getPsIfdrop(Pointer p) {
      return p.getInt(PS_IFDROP_OFFSET);
    }
  };

  public static class win_pcap_stat extends pcap_stat {

    public static final int BS_CAPT_OFFSET;

    public int bs_capt; // u_int

    static {
      win_pcap_stat ph = new win_pcap_stat();
      BS_CAPT_OFFSET = ph.fieldOffset("bs_capt");
    }

    public win_pcap_stat() {}

    public win_pcap_stat(Pointer p) {
      super(p);
      read();
    }

    public static class ByReference extends win_pcap_stat implements Structure.ByReference {}

    @Override
    protected List<String> getFieldOrder() {
      List<String> list = super.getFieldOrder();
      list.add("bs_capt");
      return list;
    }

    static int getBsCapt(Pointer p) {
      return p.getInt(BS_CAPT_OFFSET);
    }
  };

  public static class pcap_stat_ex extends Structure {

    public NativeLong rx_packets; /* total packets received       */ // u_long
    public NativeLong tx_packets; /* total packets transmitted    */ // u_long
    public NativeLong rx_bytes; /* total bytes received         */ // u_long
    public NativeLong tx_bytes; /* total bytes transmitted      */ // u_long
    public NativeLong rx_errors; /* bad packets received         */ // u_long
    public NativeLong tx_errors; /* packet transmit problems     */ // u_long
    public NativeLong rx_dropped; /* no space in Rx buffers       */ // u_long
    public NativeLong tx_dropped; /* no space available for Tx    */ // u_long
    public NativeLong multicast; /* multicast packets received   */ // u_long
    public NativeLong collisions; // u_long

    /* detailed rx_errors: */
    public NativeLong rx_length_errors; // u_long
    public NativeLong rx_over_errors; /* receiver ring buff overflow  */ // u_long
    public NativeLong rx_crc_errors; /* recv'd pkt with crc error    */ // u_long
    public NativeLong rx_frame_errors; /* recv'd frame alignment error */ // u_long
    public NativeLong rx_fifo_errors; /* recv'r fifo overrun          */ // u_long
    public NativeLong rx_missed_errors; /* recv'r missed packet         */ // u_long

    /* detailed tx_errors */
    public NativeLong tx_aborted_errors; // u_long
    public NativeLong tx_carrier_errors; // u_long
    public NativeLong tx_fifo_errors; // u_long
    public NativeLong tx_heartbeat_errors; // u_long
    public NativeLong tx_window_errors; // u_long

    public pcap_stat_ex() {}

    public static class ByReference extends pcap_stat_ex implements Structure.ByReference {}

    @Override
    protected List<String> getFieldOrder() {
      List<String> list = new ArrayList<String>();
      list.add("rx_packets");
      list.add("tx_packets");
      list.add("rx_bytes");
      list.add("tx_bytes");
      list.add("rx_errors");
      list.add("tx_errors");
      list.add("rx_dropped");
      list.add("tx_dropped");
      list.add("multicast");
      list.add("collisions");
      list.add("rx_length_errors");
      list.add("rx_over_errors");
      list.add("rx_crc_errors");
      list.add("rx_frame_errors");
      list.add("rx_fifo_errors");
      list.add("rx_missed_errors");
      list.add("tx_aborted_errors");
      list.add("tx_carrier_errors");
      list.add("tx_fifo_errors");
      list.add("tx_heartbeat_errors");
      list.add("tx_window_errors");
      return list;
    }
  };

  public static class PcapErrbuf extends Structure {

    public byte[] buf = new byte[PCAP_ERRBUF_SIZE()];

    public PcapErrbuf() {}

    private static int PCAP_ERRBUF_SIZE() {
      return 256;
    }

    public int length() {
      return toString().length();
    }

    @Override
    protected List<String> getFieldOrder() {
      List<String> list = new ArrayList<String>();
      list.add("buf");
      return list;
    }

    @Override
    public String toString() {
      return Native.toString(buf);
    }
  }
}
