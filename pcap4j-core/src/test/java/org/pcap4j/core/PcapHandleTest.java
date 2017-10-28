package org.pcap4j.core;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.PcapHandle.PcapDirection;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.LinuxSllPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.pcap4j.packet.namednumber.LinuxSllPacketType;
import org.pcap4j.util.ByteArrays;

import java.io.EOFException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

@SuppressWarnings("javadoc")
public class PcapHandleTest {

  private PcapHandle ph;

  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
  }

  @AfterClass
  public static void tearDownAfterClass() throws Exception {
  }

  @Before
  public void setUp() throws Exception {
    ph = Pcaps.openOffline(
           "src/test/resources/org/pcap4j/core/PcapHandleTest.pcap"
         );
  }

  @After
  public void tearDown() throws Exception {
    if (ph != null) {
      ph.close();
    }
  }

  @Test
  public void testGetStats() throws Exception {
    if (ph != null) {
      ph.close();
    }

    List<PcapNetworkInterface> nifs = Pcaps.findAllDevs();
    if (nifs.isEmpty()) {
      ph = Pcaps.openDead(DataLinkType.EN10MB, 2048);
      try {
        ph.getStats();
        fail("getStats on a pcap_open_dead pcap_t should throw a PcapNativeException.");
      } catch (PcapNativeException e) {
        assertEquals("Statistics aren't available from a pcap_open_dead pcap_t", e.getMessage());
      }
    }
    else {
      ph = nifs.get(0).openLive(55555, PromiscuousMode.PROMISCUOUS, 100);
      PcapStat ps = ph.getStats();
      assertNotNull(ps);
    }
  }

  @Test
  public void testListDatalinks() throws Exception {
    List<DataLinkType> list = ph.listDatalinks();
    assertNotNull(list);
    assertEquals(1, list.size());
    assertEquals(DataLinkType.EN10MB, list.get(0));
  }

  @Test
  public void testSetDlt() throws Exception {
    ph.setDlt(ph.getDlt());
  }

  @Test
  public void testGetTimestamp() throws Exception {
    PcapPacket p = ph.getNextPacket();
    assertEquals(1434220771L, p.getTimestamp().getEpochSecond());
  }

  @Test
  public void testGetTimestampEx() throws Exception {
    PcapPacket p = ph.getNextPacketEx();
    assertEquals(1434220771L, p.getTimestamp().getEpochSecond());
  }


  @Test
  public void testGetTimestampLoop() throws Exception {
    ph.loop(1, packet -> assertEquals(1434220771L, packet.getTimestamp().getEpochSecond()));
  }

  @Test
  public void testGetOriginalLength() throws Exception {
    PcapPacket packet = ph.getNextPacket();
    assertEquals(74, packet.getOriginalLength());
    assertEquals(packet.length(), packet.getOriginalLength());
  }

  @Test
  public void testGetOriginalLengthEx() throws Exception {
    PcapPacket packet = ph.getNextPacketEx();
    assertEquals(74, packet.getOriginalLength());
    assertEquals(packet.length(), packet.getOriginalLength());
  }

  @Test
  public void testGetOriginalLengthLoop() throws Exception {
    ph.loop(1, packet -> {
      assertEquals(74, packet.getOriginalLength());
      assertEquals(packet.length(), packet.getOriginalLength());
    });
  }

  @Test
  public void testSetDirection() throws Exception {
    if (System.getenv("TRAVIS") != null) {
      // run only on Travis CI
      PcapNetworkInterface nif = Pcaps.getDevByName("any");
      PcapHandle handle = nif.openLive(65536, PromiscuousMode.PROMISCUOUS, 10);
      handle.setDirection(PcapDirection.OUT);
      handle.setFilter("icmp", BpfCompileMode.OPTIMIZE);

      ProcessBuilder pb = new ProcessBuilder("/bin/ping", "www.google.com");
      Process process = pb.start();

      final List<Packet> packets = new ArrayList<Packet>();
      handle.loop(3, packet -> packets.add(packet));
      handle.close();
      process.destroy();

      assertEquals(3, packets.size());

      for (Packet packet: packets) {
        byte[] rawData = packet.getRawData();
        LinuxSllPacket sll = LinuxSllPacket.newPacket(rawData, 0, rawData.length);
        assertEquals(LinuxSllPacketType.LINUX_SLL_OUTGOING, sll.getHeader().getPacketType());
      }
    }
    else {
      try {
        ph.setDirection(PcapDirection.OUT);
        fail();
      } catch (PcapNativeException e) {
        assertTrue(e.getMessage().startsWith("Failed to set direction:"));
      }
    }
  }

  @Test
  public void testDirection() throws Exception {
    if (System.getenv("TRAVIS") != null) {
      // run only on Travis CI
      PcapHandle handle
        = new PcapHandle.Builder("any")
            .direction(PcapDirection.IN)
            .promiscuousMode(PromiscuousMode.PROMISCUOUS)
            .snaplen(65536)
            .timeoutMillis(10)
            .build();
      handle.setFilter("icmp", BpfCompileMode.OPTIMIZE);

      ProcessBuilder pb = new ProcessBuilder("/bin/ping", "www.google.com");
      Process process = pb.start();

      final List<Packet> packets = new ArrayList<Packet>();
      handle.loop(3, packet -> packets.add(packet));
      handle.close();
      process.destroy();

      assertEquals(3, packets.size());

      for (Packet packet: packets) {
        byte[] rawData = packet.getRawData();
        LinuxSllPacket sll = LinuxSllPacket.newPacket(rawData, 0, rawData.length);
        assertEquals(LinuxSllPacketType.LINUX_SLL_HOST, sll.getHeader().getPacketType());
      }
    }
  }

  @Test
  public void testSetFilterIcmp() throws Exception {
    PcapHandle handle = null;
    try {
      handle
        = Pcaps.openOffline(
            "src/test/resources/org/pcap4j/core/udp_tcp_icmp.pcap"
          );
      handle.setFilter("icmp", BpfCompileMode.OPTIMIZE);
      int count = 0;
      try {
        while (true) {
          Packet p = handle.getNextPacketEx();
          assertNotNull(p);
          byte[] rawData = p.getRawData();
          assertEquals(60, rawData.length);
          count++;
        }
      } catch (EOFException e) {}
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
      handle
        = Pcaps.openOffline(
            "src/test/resources/org/pcap4j/core/udp_tcp_icmp.pcap"
          );
      prog = handle.compileFilter(
        "udp", BpfCompileMode.OPTIMIZE, PcapHandle.PCAP_NETMASK_UNKNOWN
      );
      handle.setFilter(prog);
      int count = 0;
      try {
        while (true) {
          Packet p = handle.getNextPacketEx();
          assertNotNull(p);
          byte[] rawData = p.getRawData();
          assertEquals(66, rawData.length);
          count++;
        }
      } catch (EOFException e) {}
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

  @Test
  public void testSendPacket() throws Exception {
    if (System.getenv("TRAVIS") != null) {
      // run only on Travis CI
      PcapNetworkInterface nif = Pcaps.getDevByName("lo");
      final PcapHandle handle = nif.openLive(65536, PromiscuousMode.PROMISCUOUS, 10);
      byte[] sendingRawPacket = new byte[50];
      sendingRawPacket[0] = 1;
      sendingRawPacket[1] = 2;
      sendingRawPacket[2] = 3;
      sendingRawPacket[3] = 4;
      sendingRawPacket[4] = 5;
      Packet sendingPacket = UnknownPacket.newPacket(sendingRawPacket, 0, sendingRawPacket.length);

      ExecutorService pool = Executors.newSingleThreadExecutor();
      final byte[] result = new byte[sendingRawPacket.length];
      final FutureTask<byte[]> future
        = new FutureTask<byte[]>(
            () -> {},
            result
          );
      pool.execute(
        () -> {
          try {
            handle.loop(
              -1,
              packet -> {
                byte[] p = packet.getRawData();
                if (p[0] == 1 && p[1] == 2 && p[2] == 3 && p[3] == 4 && p[4] == 5) {
                  assertEquals(result.length, p.length);
                  System.arraycopy(p, 0, result, 0, result.length);
                  future.run();
                }
              }
            );
          } catch (PcapNativeException e) {
          } catch (InterruptedException e) {
          } catch (NotOpenException e) {
          }
        }
      );

      Thread.sleep(1000);
      handle.sendPacket(sendingPacket);
      future.get(5, TimeUnit.SECONDS);
      handle.breakLoop();
      handle.close();
      assertArrayEquals(sendingRawPacket, result);
    }
  }

  @Test
  public void testSendPacketWithLen() throws Exception {
    if (System.getenv("TRAVIS") != null) {
      // run only on Travis CI
      PcapNetworkInterface nif = Pcaps.getDevByName("lo");
      final PcapHandle handle = nif.openLive(65536, PromiscuousMode.PROMISCUOUS, 10);
      byte[] sendingRawPacket = new byte[100];
      sendingRawPacket[0] = 1;
      sendingRawPacket[1] = 2;
      sendingRawPacket[2] = 3;
      sendingRawPacket[3] = 4;
      sendingRawPacket[4] = 5;

      ExecutorService pool = Executors.newSingleThreadExecutor();
      final byte[] result = new byte[50];
      final FutureTask<byte[]> future
        = new FutureTask<byte[]>(
            () -> {},
            result
          );
      pool.execute(
        () -> {
          try {
            handle.loop(
              -1,
              packet -> {
                byte[] p = packet.getRawData();
                if (p[0] == 1 && p[1] == 2 && p[2] == 3 && p[3] == 4 && p[4] == 5) {
                  Assert.assertEquals(result.length, p.length);
                  System.arraycopy(p, 0, result, 0, result.length);
                  future.run();
                }
              }
            );
          } catch (PcapNativeException e) {
          } catch (InterruptedException e) {
          } catch (NotOpenException e) {
          }
        }
      );

      Thread.sleep(1000);
      handle.sendPacket(sendingRawPacket, result.length);
      future.get(5, TimeUnit.SECONDS);
      handle.breakLoop();
      handle.close();
      assertArrayEquals(ByteArrays.getSubArray(sendingRawPacket, 0, result.length), result);
    }
  }

  @Test
  public void testStream() throws Exception {
    try (
      PcapHandle handle
           = Pcaps.openOffline("src/test/resources/org/pcap4j/core/udp_tcp_icmp.pcap");
      Stream<PcapPacket> stream = handle.stream()
    ) {
      Iterator<PcapPacket> iter = stream
        .limit(4)
        .iterator();

      assertTrue(iter.hasNext());
      assertEquals(66, iter.next().getOriginalLength());
      assertTrue(iter.hasNext());
      assertEquals(98, iter.next().getOriginalLength());
      assertTrue(iter.hasNext());
      assertEquals(60, iter.next().getOriginalLength());
      assertTrue(iter.hasNext());
      assertNull(iter.next());
      assertFalse(iter.hasNext());
    }
  }

  @Test
  public void testImmediateMode() throws Exception {
    if (System.getenv("TRAVIS") != null) {
      // run only on Travis CI
      PcapHandle handle
        = new PcapHandle.Builder("any")
        .immediateMode(true)
        .promiscuousMode(PromiscuousMode.PROMISCUOUS)
        .snaplen(65536)
        .timeoutMillis(Integer.MAX_VALUE)
        .build();

      ProcessBuilder pb = new ProcessBuilder("/bin/ping", "www.google.com");
      Process process = pb.start();

      handle.loop(3, packet -> {
        // Do nothing.
      });
      handle.close();
      process.destroy();
    }
  }

}
