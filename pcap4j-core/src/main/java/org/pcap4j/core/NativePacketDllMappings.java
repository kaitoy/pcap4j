/*_##########################################################################
  _##
  _##  Copyright (C) 2015  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.core;

import com.sun.jna.Native;
import com.sun.jna.NativeLibrary;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import java.util.ArrayList;
import java.util.List;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.6.2
 */
final class NativePacketDllMappings {

  static final String LIB_NAME =
      System.getProperty(
          NativePacketDllMappings.class.getPackage().getName() + ".packetLibName", "Packet");

  static final int PACKET_OID_DATA_SIZE;

  static {
    Native.register(NativePacketDllMappings.class, NativeLibrary.getInstance(LIB_NAME));

    PACKET_OID_DATA_SIZE = new PACKET_OID_DATA().size();
  }

  // LPADAPTER PacketOpenAdapter(PCHAR AdapterNameWA)
  static native Pointer PacketOpenAdapter(String AdapterNameWA);

  // BOOLEAN PacketRequest(LPADAPTER  AdapterObject,BOOLEAN Set,PPACKET_OID_DATA  OidData)
  static native int PacketRequest(Pointer AdapterObject, int Set, PACKET_OID_DATA OidData);

  // VOID PacketCloseAdapter(LPADAPTER lpAdapter)
  static native void PacketCloseAdapter(Pointer lpAdapter);

  private NativePacketDllMappings() {}

  // struct _PACKET_OID_DATA {
  //     ULONG Oid;       ///< OID code. See the Microsoft DDK documentation or the file
  // ntddndis.h
  //                      ///< for a complete list of valid codes.
  //     ULONG Length;    ///< Length of the data field
  //     UCHAR Data[1];   ///< variable-lenght field that contains the information passed to or
  // received
  //                      ///< from the adapter.
  // };
  public static class PACKET_OID_DATA extends Structure {

    public NativeLong Oid; // ULONG
    public NativeLong Length; // ULONG
    public byte[] Data = new byte[6]; // UCHAR

    public PACKET_OID_DATA() {}

    public PACKET_OID_DATA(Pointer p) {
      super(p);
      read();
    }

    public static class ByReference extends PACKET_OID_DATA implements Structure.ByReference {}

    @Override
    protected List<String> getFieldOrder() {
      List<String> list = new ArrayList<String>();
      list.add("Oid");
      list.add("Length");
      list.add("Data");
      return list;
    }
  }
}
