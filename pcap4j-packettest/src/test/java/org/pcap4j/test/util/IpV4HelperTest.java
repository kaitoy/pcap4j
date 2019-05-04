/*_##########################################################################
  _##
  _##  Copyright (C) 2012 Pcap4J.org
  _##
  _##########################################################################
*/
package org.pcap4j.test.util;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IcmpV4EchoPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Rfc1349Tos;
import org.pcap4j.packet.SimpleBuilder;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IcmpV4Code;
import org.pcap4j.packet.namednumber.IcmpV4Type;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.test.packet.AbstractPacketTest;
import org.pcap4j.util.IpV4Helper;
import org.pcap4j.util.MacAddress;

@SuppressWarnings("javadoc")
public class IpV4HelperTest {

  private String resourceDir;
  private String tmpDirPath;

  @BeforeClass
  public static void setUpBeforeClass() throws Exception {}

  @AfterClass
  public static void tearDownAfterClass() throws Exception {}

  @Before
  public void setUp() throws Exception {
    resourceDir = System.getProperty(AbstractPacketTest.RESOURCE_DIR_PROP, "src/test/resources");
    tmpDirPath = System.getProperty(AbstractPacketTest.TMP_DIR_PROP, "testdata");

    File tmpDir = new File(tmpDirPath);
    if (!tmpDir.exists()) {
      if (!tmpDir.mkdirs()) {
        throw new IOException("Failed to make a test diectory: " + tmpDirPath);
      }
    }
  }

  @After
  public void tearDown() throws Exception {}

  @Test
  public void testFragmentDefragment() throws Exception {
    String dumpFile =
        new StringBuilder()
            .append(tmpDirPath)
            .append("/")
            .append(getClass().getSimpleName())
            .append(".pcap")
            .toString();

    UnknownPacket.Builder unknownb = new UnknownPacket.Builder();
    unknownb.rawData(new byte[4000]);

    IcmpV4EchoPacket.Builder echob = new IcmpV4EchoPacket.Builder();
    echob.identifier((short) 1234).sequenceNumber((short) 4321).payloadBuilder(unknownb);

    IcmpV4CommonPacket.Builder icmpV4b = new IcmpV4CommonPacket.Builder();
    icmpV4b
        .type(IcmpV4Type.ECHO)
        .code(IcmpV4Code.NO_CODE)
        .payloadBuilder(echob)
        .correctChecksumAtBuild(true);

    IpV4Packet.Builder ipv4b = new IpV4Packet.Builder();
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

    EthernetPacket.Builder eb = new EthernetPacket.Builder();
    eb.dstAddr(MacAddress.getByName("fe:00:00:00:00:02"))
        .srcAddr(MacAddress.getByName("fe:00:00:00:00:01"))
        .type(EtherType.IPV4)
        .payloadBuilder(ipv4b)
        .paddingAtBuild(true);

    EthernetPacket orgPacket = eb.build();

    PcapHandle handle = Pcaps.openDead(DataLinkType.EN10MB, 65536);
    PcapDumper dumper = handle.dumpOpen(dumpFile);
    Timestamp ts = new Timestamp(0);
    dumper.dump(orgPacket, ts);

    List<IpV4Packet> list = new ArrayList<IpV4Packet>();
    for (IpV4Packet p : IpV4Helper.fragment((IpV4Packet) orgPacket.getPayload(), 987)) {
      EthernetPacket ep = eb.payloadBuilder(new SimpleBuilder(p)).build();
      dumper.dump(ep, ts);
      list.add(p);
    }

    dumper.close();
    handle.close();

    Collections.shuffle(list);
    assertEquals(
        orgPacket, eb.payloadBuilder(new SimpleBuilder(IpV4Helper.defragment(list))).build());

    FileInputStream in1 =
        new FileInputStream(
            new StringBuilder()
                .append(resourceDir)
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
}
