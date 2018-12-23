package org.pcap4j.sample;

import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.NifSelector;

@SuppressWarnings("javadoc")
public class HeavyLoop {

  private HeavyLoop() {}

  public static void main(String[] args) throws PcapNativeException, NotOpenException {
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

    final PcapHandle handle = nif.openLive(65536, PromiscuousMode.PROMISCUOUS, 10);

    PacketListener listener =
        new PacketListener() {
          @Override
          public void gotPacket(Packet packet) {
            System.out.println(handle.getTimestamp());

            System.out.println("start a heavy task");
            try {
              Thread.sleep(5000);
            } catch (InterruptedException e) {

            }
            System.out.println("done");
          }
        };

    try {
      ExecutorService pool = Executors.newCachedThreadPool();
      handle.loop(5, listener, pool); // This is better than handle.loop(5, listener);
      pool.shutdown();
    } catch (InterruptedException e) {
      e.printStackTrace();
    }

    handle.close();
  }
}
