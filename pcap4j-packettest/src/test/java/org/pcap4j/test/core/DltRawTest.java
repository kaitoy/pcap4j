package org.pcap4j.test.core;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.StringReader;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.sql.Timestamp;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IcmpV4EchoPacket;
import org.pcap4j.packet.IcmpV6CommonPacket;
import org.pcap4j.packet.IcmpV6EchoRequestPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Rfc1349Tos;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.IpV6SimpleFlowLabel;
import org.pcap4j.packet.IpV6SimpleTrafficClass;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.SimpleBuilder;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.pcap4j.packet.namednumber.IcmpV4Code;
import org.pcap4j.packet.namednumber.IcmpV4Type;
import org.pcap4j.packet.namednumber.IcmpV6Code;
import org.pcap4j.packet.namednumber.IcmpV6Type;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.test.packet.AbstractPacketTest;

@SuppressWarnings("javadoc")
public class DltRawTest {

  private String originalLineSeparator;
  private String resourceDirPath;
  private String tmpDirPath;

  private final Packet ipV4 = newIpV4Packet();
  private final Packet ipV6 = newIpV6Packet();

  @Before
  public void setUp() throws Exception {
    originalLineSeparator = System.setProperty("line.separator", "\r\n");
    resourceDirPath =
        System.getProperty(AbstractPacketTest.RESOURCE_DIR_PROP, "src/test/resources");
    tmpDirPath = System.getProperty(AbstractPacketTest.TMP_DIR_PROP, "testdata");

    File tmpDir = new File(tmpDirPath);
    if (!tmpDir.exists()) {
      if (!tmpDir.mkdirs()) {
        throw new IOException("Failed to make a test diectory: " + tmpDirPath);
      }
    }
  }

  @After
  public void tearDown() throws Exception {
    System.setProperty("line.separator", originalLineSeparator);
  }

  @Test
  public void testDump() throws Exception {
    String dumpFile =
        new StringBuilder()
            .append(tmpDirPath)
            .append("/")
            .append(getClass().getSimpleName())
            .append(".pcap")
            .toString();
    PcapHandle handle = Pcaps.openDead(DataLinkType.RAW, 65536);
    PcapDumper dumper = handle.dumpOpen(dumpFile);
    Timestamp ts = new Timestamp(0);
    dumper.dump(ipV4, ts);
    dumper.dump(ipV6, ts);
    dumper.close();
    handle.close();

    FileInputStream in1 =
        new FileInputStream(
            new StringBuilder()
                .append(resourceDirPath)
                .append("/")
                .append(getClass().getSimpleName())
                .append(".pcap")
                .toString());
    FileInputStream in2 = new FileInputStream(dumpFile);

    byte[] buffer1 = new byte[100];
    byte[] buffer2 = new byte[100];
    int size;
    while ((size = in1.read(buffer1)) != -1) {
      assertEquals(size, in2.read(buffer2));
      assertArrayEquals(buffer1, buffer2);
    }

    in1.close();
    in2.close();
  }

  @Test
  public void testRead() throws Exception {
    String pcapFile =
        new StringBuilder()
            .append(resourceDirPath)
            .append("/")
            .append(getClass().getSimpleName())
            .append(".pcap")
            .toString();
    PcapHandle ph = Pcaps.openOffline(pcapFile);
    StringBuilder sb = new StringBuilder(1000);
    sb.append(ph.getNextPacket().toString())
        .append(System.getProperty("line.separator"))
        .append(ph.getNextPacket().toString());
    ph.close();

    FileReader fr =
        new FileReader(
            new StringBuilder()
                .append(resourceDirPath)
                .append("/")
                .append(getClass().getSimpleName())
                .append(".log")
                .toString());
    BufferedReader fbr = new BufferedReader(fr);
    StringReader sr = new StringReader(sb.toString());
    BufferedReader sbr = new BufferedReader(sr);

    String line;
    while ((line = fbr.readLine()) != null) {
      assertEquals(line, sbr.readLine());
    }

    assertNull(sbr.readLine());

    fbr.close();
    fr.close();
    sr.close();
    sbr.close();
  }

  private static Packet newIpV4Packet() {
    short identifier = (short) 1234;
    short sequenceNumber = (short) 4321;

    UnknownPacket.Builder unknownb = new UnknownPacket.Builder();
    unknownb.rawData(new byte[] {(byte) 0, (byte) 1, (byte) 2, (byte) 3});

    IcmpV4EchoPacket.Builder b = new IcmpV4EchoPacket.Builder();
    b.identifier(identifier).sequenceNumber(sequenceNumber).payloadBuilder(unknownb);
    IcmpV4EchoPacket packet = b.build();

    IcmpV4CommonPacket.Builder icmpV4b = new IcmpV4CommonPacket.Builder();
    icmpV4b
        .type(IcmpV4Type.ECHO)
        .code(IcmpV4Code.NO_CODE)
        .payloadBuilder(new SimpleBuilder(packet))
        .correctChecksumAtBuild(true);

    IpV4Packet.Builder ipv4b = new IpV4Packet.Builder();
    try {
      ipv4b
          .version(IpVersion.IPV4)
          .tos(IpV4Rfc1349Tos.newInstance((byte) 0))
          .identification((short) 100)
          .ttl((byte) 100)
          .protocol(IpNumber.ICMPV4)
          .srcAddr(
              (Inet4Address)
                  InetAddress.getByAddress(new byte[] {(byte) 192, (byte) 0, (byte) 2, (byte) 1}))
          .dstAddr(
              (Inet4Address)
                  InetAddress.getByAddress(new byte[] {(byte) 192, (byte) 0, (byte) 2, (byte) 2}))
          .payloadBuilder(icmpV4b)
          .correctChecksumAtBuild(true)
          .correctLengthAtBuild(true);
    } catch (UnknownHostException e) {
      throw new AssertionError("Never get here.");
    }

    return ipv4b.build();
  }

  private static Packet newIpV6Packet() {
    short identifier = (short) 1234;
    short sequenceNumber = (short) 4321;

    UnknownPacket.Builder unknownb = new UnknownPacket.Builder();
    unknownb.rawData(new byte[] {(byte) 0, (byte) 1, (byte) 2, (byte) 3});

    IcmpV6EchoRequestPacket.Builder b = new IcmpV6EchoRequestPacket.Builder();
    b.identifier(identifier).sequenceNumber(sequenceNumber).payloadBuilder(unknownb);
    Packet packet = b.build();

    Inet6Address srcAddr;
    Inet6Address dstAddr;
    try {
      srcAddr = (Inet6Address) InetAddress.getByName("2001:db8::3:2:1");
      dstAddr = (Inet6Address) InetAddress.getByName("2001:db8::3:2:2");
    } catch (UnknownHostException e) {
      throw new AssertionError();
    }
    IcmpV6CommonPacket.Builder icmpV6b = new IcmpV6CommonPacket.Builder();
    icmpV6b
        .type(IcmpV6Type.ECHO_REQUEST)
        .code(IcmpV6Code.NO_CODE)
        .srcAddr(srcAddr)
        .dstAddr(dstAddr)
        .payloadBuilder(new SimpleBuilder(packet))
        .correctChecksumAtBuild(true);

    IpV6Packet.Builder ipv6b = new IpV6Packet.Builder();
    ipv6b
        .version(IpVersion.IPV6)
        .trafficClass(IpV6SimpleTrafficClass.newInstance((byte) 0x12))
        .flowLabel(IpV6SimpleFlowLabel.newInstance(0x12345))
        .nextHeader(IpNumber.ICMPV6)
        .hopLimit((byte) 100)
        .srcAddr(srcAddr)
        .dstAddr(dstAddr)
        .correctLengthAtBuild(true)
        .payloadBuilder(icmpV6b);

    return ipv6b.build();
  }
}
