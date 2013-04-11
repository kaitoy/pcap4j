/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.core;

import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;
import com.sun.jna.Callback;
import com.sun.jna.Function;
import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.NativeLibrary;
import com.sun.jna.NativeLong;
import com.sun.jna.Platform;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.ptr.PointerByReference;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
final class NativeMappings {

  static final String PCAP_LIB_NAME
    = System.getProperty(
        NativeMappings.class.getPackage().getName() + ".pcapLibName",
        Platform.isWindows() ? "wpcap" : "pcap"
      );

  static final Function PCAP_DUMP
    = Function.getFunction(
        PCAP_LIB_NAME,
        "pcap_dump"
      );

  // LITTLE_ENDIAN: SPARC, JVM
  // BIG_ENDIAN: x86, network bite order
  static final ByteOrder NATIVE_BYTE_ORDER = ByteOrder.nativeOrder();

  static final int SBIOCSTIME = 0x4201;

  static final Pointer ERRNO_P
    = Platform.isSolaris() ? NativeLibrary.getInstance(PCAP_LIB_NAME)
                               .getGlobalVariableAddress("errno")
                           : null;

  // see pcap-int.h: struct pcap
  static int getFdFromPcapT(Pointer p) {
    if (Platform.isWindows()) { return -1; }
    return p.getInt(0);
  }

  static {
    // Native.register(PCAP_LIB_NAME);
    Native.register(
      NativeMappings.class,
      NativeLibrary.getInstance(PCAP_LIB_NAME)
    );
  }

  // direct mappings
  static native int pcap_findalldevs(PointerByReference alldevsp, PcapErrbuf errbuf);

  static native void pcap_freealldevs(Pointer alldevsp);

  static native Pointer pcap_lookupdev(PcapErrbuf errbuf);

  static native  Pointer pcap_open_live(
    String device, int snaplen, int promisc, int to_ms, PcapErrbuf errbuf
  );

  static native Pointer pcap_open_dead(int linktype, int snaplen);

  static native Pointer pcap_open_offline(String fname, PcapErrbuf errbuf);

  static native Pointer pcap_dump_open(Pointer p, String fname);

  static native void pcap_dump(Pointer user, pcap_pkthdr header, byte[] packet);

  static native void pcap_dump_close(Pointer p);

  static native Pointer pcap_next(Pointer p, pcap_pkthdr h);

  static native int pcap_next_ex(Pointer p, PointerByReference h, PointerByReference data);

  static native int pcap_loop(Pointer p, int cnt, pcap_handler callback, Pointer user);

  static native int pcap_loop(Pointer p, int cnt, Function callback, Pointer user);

  static native void pcap_breakloop(Pointer p);

  static native int pcap_compile(
    Pointer p, bpf_program fp, String str, int optimize, int netmask
  );

  static native int pcap_setfilter(Pointer p, bpf_program fp);

  static native void  pcap_freecode(bpf_program fp);

  static native int pcap_sendpacket(Pointer p, byte buf[], int size);

  static native void pcap_close(Pointer p);

  static native int pcap_datalink(Pointer p);

  static native Pointer pcap_geterr(Pointer p);

  static native Pointer pcap_strerror(int errno);

  // interface mappings
  interface PcapLibrary extends Library {
    static final PcapLibrary INSTANCE
      = (PcapLibrary)Native.loadLibrary(
          PCAP_LIB_NAME,
          PcapLibrary.class
        );

    // int pcap_findalldevs(pcap_if_t **alldevsp, char *errbuf)
    @Deprecated // Use direct mapped one instead.
    int pcap_findalldevs(PointerByReference alldevsp, PcapErrbuf errbuf);
    // TODO WinPcap: int pcap_findalldevs_ex(char *host, char *port, SOCKET sockctrl, struct pcap_rmtauth *auth, pcap_if_t **alldevs, char *errbuf)

    // void  pcap_freealldevs (pcap_if_t *alldevsp)
    @Deprecated // Use direct mapped one instead.
    void pcap_freealldevs(Pointer alldevsp);

    // char *pcap_lookupdev(char *errbuf)
    @Deprecated // Use direct mapped one instead.
    Pointer pcap_lookupdev(PcapErrbuf errbuf);

    // pcap_t *pcap_open_live(
    //   const char *device, int snaplen, int promisc, int to_ms, char *errbuf
    // )
    @Deprecated // Use direct mapped one instead.
    Pointer pcap_open_live(
      String device, int snaplen, int promisc, int to_ms, PcapErrbuf errbuf
    );

    // pcap_t *pcap_open_dead (int linktype, int snaplen)
    @Deprecated // Use direct mapped one instead.
    Pointer pcap_open_dead(int linktype, int snaplen);

    // pcap_t *pcap_open_offline(const char *fname, char *errbuf)
    @Deprecated // Use direct mapped one instead.
    Pointer pcap_open_offline(String fname, PcapErrbuf errbuf);

    // TODO WinPcap: pcap_t *pcap_open(const char *source, int snaplen, int flags, int read_timeout, struct pcap_rmtauth *auth, char *errbuf)

    // pcap_dumper_t *pcap_dump_open(pcap_t *p, const char *fname)
    @Deprecated // Use direct mapped one instead.
    Pointer pcap_dump_open(Pointer p, String fname);

    // void pcap_dump(u_char *user, const struct pcap_pkthdr *h, const u_char *sp)
    @Deprecated // Use direct mapped one instead.
    void pcap_dump(Pointer user, pcap_pkthdr header, byte[] packet);

    // void pcap_dump_close(pcap_dumper_t *p)
    @Deprecated // Use direct mapped one instead.
    void pcap_dump_close(Pointer p);

    // TODO WinPcap: int pcap_live_dump(pcap_t *p, char *filename, int maxsize, int maxpacks)

    // u_char *pcap_next(pcap_t *p, struct pcap_pkthdr *h)
    @Deprecated // Use direct mapped one instead.
    Pointer pcap_next(Pointer p, pcap_pkthdr h);

    // int pcap_next_ex(pcap_t *p, struct pcap_pkthdr **h, const u_char **data)
    @Deprecated // Use direct mapped one instead.
    int pcap_next_ex(Pointer p, PointerByReference h, PointerByReference data);

    // int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
    @Deprecated // Use direct mapped one instead.
    int pcap_loop(Pointer p, int cnt, pcap_handler callback, Pointer user);
    @Deprecated // Use direct mapped one instead.
    int pcap_loop(Pointer p, int cnt, Function callback, Pointer user);

    // void pcap_breakloop(pcap_t *p)
    @Deprecated // Use direct mapped one instead.
    void pcap_breakloop(Pointer p);

    // int pcap_compile(
    //   pcap_t *p, struct bpf_program *fp, char *str,
    //   int optimize, bpf_u_int32 netmask
    // )
    @Deprecated // Use direct mapped one instead.
    int pcap_compile(
      Pointer p, bpf_program fp, String str, int optimize, int netmask
    );

    // int pcap_setfilter(pcap_t *p, struct bpf_program *fp)
    @Deprecated // Use direct mapped one instead.
    int pcap_setfilter(Pointer p, bpf_program fp);

    // void pcap_freecode(struct bpf_program *fp)
    @Deprecated // Use direct mapped one instead.
    void  pcap_freecode(bpf_program fp);

    // int pcap_sendpacket(pcap_t *p, const u_char *buf, int size)
    @Deprecated // Use direct mapped one instead.
    int pcap_sendpacket(Pointer p, byte buf[], int size);

    // void pcap_close(pcap_t *p)
    @Deprecated // Use direct mapped one instead.
    void pcap_close(Pointer p);

    // int pcap_datalink(pcap_t *p)
    @Deprecated // Use direct mapped one instead.
    int pcap_datalink(Pointer p);

    // char *pcap_geterr(pcap_t *p)
    @Deprecated // Use direct mapped one instead.
    Pointer pcap_geterr(Pointer p);

    // char *pcap_strerror(int errno)
    @Deprecated // Use direct mapped one instead.
    Pointer pcap_strerror(int errno);

    // int strioctl(int fd, int cmd, int len, char *dp)
    int strioctl(int fd, int cmd, int len, Pointer dp);  // Can't map directly because not all OSes support this function.

  }

  static interface pcap_handler extends Callback {
    // void got_packet(
    //   u_char *args, const struct pcap_pkthdr *header, const u_char *packet
    // );
    public void got_packet(Pointer args, pcap_pkthdr header, Pointer packet);
  }

  public static class pcap_if extends Structure {
    public pcap_if.ByReference next; // struct pcap_if *
    public String name; // char *
    public String description; // char *
    public pcap_addr.ByReference addresses; // struct pcap_addr *
    public int flags; // bpf_u_int32

    public pcap_if() {}

    public pcap_if(Pointer p) {
      super();
      useMemory(p, 0);
      read();
    }

    public static
    class ByReference
    extends pcap_if implements Structure.ByReference {}

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
      super();
      useMemory(p, 0);
      read();
    }

    public static
    class ByReference
    extends pcap_addr implements Structure.ByReference {}

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

  // TODO sockaddr has another field on FreeBSD
  public static class sockaddr extends Structure {

    public short sa_family; // u_short
    public byte[] sa_data = new byte[14];  // char[14]

    public sockaddr() {}

    public sockaddr(Pointer p) {
      super();
      useMemory(p, 0);
      read();
    }

    public static
    class ByReference
    extends sockaddr implements Structure.ByReference {}

    @Override
    protected List<String> getFieldOrder() {
      List<String> list = new ArrayList<String>();
      list.add("sa_family");
      list.add("sa_data");
      return list;
    }

  }

  public static class sockaddr_in extends Structure {

    public short sin_family; // short
    public short sin_port; // u_short
    public in_addr sin_addr; // struct in_addr
    public byte[] sin_zero = new byte[8]; // char[8]

    public sockaddr_in() {}

    public sockaddr_in(Pointer p) {
      super();
      useMemory(p, 0);
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
      super();
      useMemory(p, 0);
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

  }

  public static class in6_addr extends Structure {

    public byte[] s6_addr = new byte[16];   // unsigned char[16]

    public in6_addr() {}

    @Override
    protected List<String> getFieldOrder() {
      List<String> list = new ArrayList<String>();
      list.add("s6_addr");
      return list;
    }

  }

  public static class pcap_pkthdr extends Structure {

    public timeval ts;// struct timeval
    public int caplen; // bpf_u_int32
    public int len;// bpf_u_int32

    public pcap_pkthdr() {}

    public pcap_pkthdr(Pointer p) {
      super();
      useMemory(p, 0);
      read();
    }

    public static
    class ByReference
    extends pcap_pkthdr implements Structure.ByReference {}

    @Override
    protected List<String> getFieldOrder() {
      List<String> list = new ArrayList<String>();
      list.add("ts");
      list.add("caplen");
      list.add("len");
      return list;
    }

  }

  public static class timeval extends Structure {

    public NativeLong tv_sec; // long
    public NativeLong tv_usec; // long

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

    public bpf_program() {}

    @Override
    protected List<String> getFieldOrder() {
      List<String> list = new ArrayList<String>();
      list.add("bf_len");
      list.add("bf_insns");
      return list;
    }

  }

  public static class  bpf_insn extends Structure {

    public short code; // u_short
    public byte jt; // u_char
    public byte jf; // u_char
    public int k; // bpf_u_int32

    public bpf_insn() {}

    public static
    class ByReference
    extends bpf_insn implements Structure.ByReference {}

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
