package org.pcap4j.test;

import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.concurrent.TimeoutException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapHandle.BpfCompileMode;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.NifSelector;

public class WriteReadPacketObjectTest {

  private static final String FILE_NAME
    = WriteReadPacketObjectTest.class.getSimpleName() + ".obj";

  public static void main(String[] args) throws PcapNativeException {
    String filter = args.length != 0 ? args[0] : "";

    PcapNetworkInterface nif;
    try {
      nif = new NifSelector().selectNetworkInterface();
    } catch (IOException e) {
      e.printStackTrace();
      return;
    }

    if (nif == null) {
      return;
    }

    System.out.println(nif.getName() + "(" + nif.getDescription() + ")");

    PcapHandle handle
      = nif.openLive(65536, PromiscuousMode.PROMISCUOUS, 5000);

    try {
      handle.setFilter(
        filter,
        BpfCompileMode.OPTIMIZE,
        InetAddress
          .getByAddress(new byte[] {(byte)255, (byte)255, (byte)255, (byte)0})
      );
    } catch (UnknownHostException e) {
      assert true; // never get here
    }

    Packet packet = null;

    while(packet == null) {
      try {
        packet = handle.getNextPacketEx();
      } catch (TimeoutException e) {
      } catch (EOFException e) {
        e.printStackTrace();
      }
    }

    handle.close();

    System.out.println(packet);

    try {
      ObjectOutputStream oos
        = new ObjectOutputStream(
            new FileOutputStream(new File(FILE_NAME))
          );
      oos.writeObject(packet);
      oos.close();
    } catch (IOException e) {
      e.printStackTrace();
      return;
    }


    ObjectInputStream ois = null;
    try {
      ois = new ObjectInputStream(new FileInputStream(new File(FILE_NAME)));
      System.out.println(ois.readObject());
      ois.close();
    } catch (FileNotFoundException e) {
      e.printStackTrace();
    } catch (IOException e) {
      e.printStackTrace();
    } catch (ClassNotFoundException e) {
      e.printStackTrace();
    }
  }

}
