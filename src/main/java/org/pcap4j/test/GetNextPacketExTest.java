package org.pcap4j.test;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapHandle.BpfCompileMode;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.NifSelector;

public class GetNextPacketExTest {

  private static final String COUNT_KEY
    = LoopTest.class.getName() + ".count";
  private static final int COUNT
    = Integer.getInteger(COUNT_KEY, 5);

  private static final String READ_TIMEOUT_KEY
    = LoopTest.class.getName() + ".readTimeOut";
  private static final int READ_TIMEOUT
    = Integer.getInteger(READ_TIMEOUT_KEY, 5000); // [ms]

  private static final String MAX_PACKT_SIZE_KEY
    = LoopTest.class.getName() + ".maxPacketSize";
  private static final int MAX_PACKT_SIZE
    = Integer.getInteger(MAX_PACKT_SIZE_KEY, 65536); // [bytes]

  public static void main(String[] args) throws PcapNativeException, FileNotFoundException, IOException {
    System.out.println(COUNT_KEY + ": " + COUNT);
    System.out.println(READ_TIMEOUT_KEY + ": " + READ_TIMEOUT);
    System.out.println(MAX_PACKT_SIZE_KEY + ": " + MAX_PACKT_SIZE);
    System.out.println("\n");

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
      = nif.openLive(MAX_PACKT_SIZE, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);

    try {
      handle.setFilter(
        args.length != 0 ? args[0] : "",
        BpfCompileMode.OPTIMIZE,
        InetAddress
          .getByAddress(new byte[] {(byte)255, (byte)255, (byte)255, (byte)0})
      );
    } catch (UnknownHostException e) {
      assert true; // never get here
    }


    ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(new File("out")));

    int num = 0;
    while (true) {
      Packet packet = handle.getNextPacketEx();
      if (packet == null) {
        continue;
      }
      else {
        System.out.println(packet);
        oos.writeObject(packet);
        num++;
        if (num >= COUNT) {
          break;
        }
      }
    }

    handle.close();
  }

}
