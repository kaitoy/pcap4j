/*_##########################################################################
  _##
  _##  Copyright (C) 2011  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.core;

import com.sun.jna.Callback;
import com.sun.jna.Library;
import com.sun.jna.Native;
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

  interface PcapLibrary extends Library {
    static final PcapLibrary INSTANCE
      = (PcapLibrary)Native.loadLibrary(
          (Platform.isWindows() ? "wpcap" : "pcap"),
          PcapLibrary.class
        );

    // int pcap_findalldevs(pcap_if_t **alldevsp, char *errbuf)
    int pcap_findalldevs(PointerByReference alldevsp, PcapErrbuf errbuf);
    // TODO WinPcap: int pcap_findalldevs_ex(char *host, char *port, SOCKET sockctrl, struct pcap_rmtauth *auth, pcap_if_t **alldevs, char *errbuf)  リモートキャプチャ可

    // void  pcap_freealldevs (pcap_if_t *alldevsp)
    void pcap_freealldevs(Pointer alldevsp);

    // char *pcap_lookupdev(char *errbuf)
    Pointer pcap_lookupdev(PcapErrbuf errbuf);

    // pcap_t *pcap_open_live(
    //   const char *device, int snaplen, int promisc, int to_ms, char *errbuf
    // )
    Pointer pcap_open_live(
      String device, int snaplen, int promisc, int to_ms, PcapErrbuf errbuf
    );
    // TODO WinPcap: pcap_t *pcap_open(const char *source, int snaplen, int flags, int read_timeout, struct pcap_rmtauth *auth, char *errbuf)

    // TODO pcap_dumper_t *pcap_dump_open(pcap_t *p, const char *fname)

    // u_char *pcap_next(pcap_t *p, struct pcap_pkthdr *h)
    Pointer pcap_next(Pointer p, pcap_pkthdr h);

    // int pcap_next_ex(pcap_t *p, struct pcap_pkthdr **h, const u_char **data)
    int pcap_next_ex(Pointer p, PointerByReference h, PointerByReference data);
    // TODO Solarisではこっちをつかわないとだめ。リードタイムアウト設定を無視される

    // int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
    int pcap_loop(Pointer p, int cnt, pcap_handler callback, String user);
    // openした時のタイムアウトを遵守しない

    // void pcap_breakloop(pcap_t *p)
    void pcap_breakloop(Pointer p);

    // int pcap_compile(
    //   pcap_t *p, struct bpf_program *fp, char *str,
    //   int optimize, bpf_u_int32 netmask
    // )
    int pcap_compile(
      Pointer p, bpf_program fp, String str, int optimize, int netmask
    );

    // int  pcap_setfilter (pcap_t *p, struct bpf_program *fp)
    int pcap_setfilter(Pointer p, bpf_program fp);

    // void  pcap_freecode (struct bpf_program *fp)
    void  pcap_freecode(bpf_program fp);

    // int pcap_sendpacket(pcap_t *p, const u_char *buf, int size)
    // int pcap_sendpacket(Pointer p, Pointer buf, int size);
    int pcap_sendpacket(Pointer p, byte buf[], int size);

    // void pcap_close(pcap_t *p)
    void pcap_close(Pointer p);

    // int pcap_datalink (pcap_t *p)
    int pcap_datalink(Pointer p);

    // char *  pcap_geterr (pcap_t *p)
    Pointer pcap_geterr(Pointer p);

  }

  static interface pcap_handler extends Callback {
    // void got_packet(
    //   u_char *args, const struct pcap_pkthdr *header, const u_char *packet
    // );
    public void got_packet(String args, pcap_pkthdr header, Pointer packet);
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
  }

  // TODO FreeBSDはフィールドがひとつ多い
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
  }

  public static class in_addr extends Structure {
    public int s_addr; // in_addr_t = uint32_t

    public in_addr() {}
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
  }

  public static class in6_addr extends Structure {
    public byte[] s6_addr = new byte[16];   // unsigned char[16]

    public in6_addr() {}
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
  }

  public static class timeval extends Structure {
    public NativeLong tv_sec; // long
    public NativeLong tv_usec; // long

    public timeval() {}
  }

  public static class bpf_program extends Structure {
    public int bf_len; // u_int
    public bpf_insn.ByReference bf_insns; // struct bpf_insn *

    public bpf_program() {}
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
  };

  public static class PcapErrbuf extends Structure {
    public byte[] buf = new byte[PCAP_ERRBUF_SIZE()];

    public PcapErrbuf() {}

    private static int PCAP_ERRBUF_SIZE() {
      return 256;
    }

    public int length() {
      return getMessage().length();
    }

    public String getMessage() {
      return Native.toString(buf);
    }
  }

}
