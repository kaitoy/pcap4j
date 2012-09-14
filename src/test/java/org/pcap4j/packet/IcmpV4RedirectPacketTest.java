package org.pcap4j.packet;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertArrayEquals;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.StringReader;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IcmpV4RedirectPacket.IcmpV4RedirectHeader;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IcmpV4Code;
import org.pcap4j.packet.namednumber.IcmpV4Type;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.util.IcmpV4Helper;
import org.pcap4j.util.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Kaito
 *
 */
public class IcmpV4RedirectPacketTest {

  private static final Logger logger
    = LoggerFactory.getLogger(IcmpV4RedirectPacketTest.class);

  private final IcmpV4RedirectPacket packet;
  private final Inet4Address gatewayInternetAddress;

  public IcmpV4RedirectPacketTest() {
    try {
      this.gatewayInternetAddress
        = (Inet4Address)InetAddress.getByAddress(
            new byte[] { (byte)192, (byte)0, (byte)2, (byte)254 }
          );
    } catch (UnknownHostException e) {
      throw new AssertionError();
    }

    IcmpV4EchoPacket.Builder echob = new IcmpV4EchoPacket.Builder();
    echob.identifier((short)100)
         .sequenceNumber((short)10)
         .payloadBuilder(
            new UnknownPacket.Builder()
              .rawData((new byte[] { (byte)0, (byte)1, (byte)2 }))
          );

    IcmpV4CommonPacket.Builder icmpV4b = new IcmpV4CommonPacket.Builder();
    icmpV4b.type(IcmpV4Type.ECHO)
           .code(IcmpV4Code.NO_CODE)
           .payloadBuilder(echob)
           .correctChecksumAtBuild(true);

    IpV4Packet.Builder ipv4b = new IpV4Packet.Builder();
    try {
      ipv4b.version(IpVersion.IPV4)
           .tos(IpV4Rfc791Tos.newInstance((byte)0))
           .identification((short)100)
           .ttl((byte)100)
           .protocol(IpNumber.ICMPV4)
           .srcAddr(
              (Inet4Address)InetAddress.getByAddress(
                new byte[] { (byte)192, (byte)0, (byte)2, (byte)2 }
              )
            )
          .dstAddr(
             (Inet4Address)InetAddress.getByAddress(
               new byte[] { (byte)192, (byte)0, (byte)2, (byte)1 }
             )
           )
          .payloadBuilder(icmpV4b)
          .correctChecksumAtBuild(true)
          .correctLengthAtBuild(true);
    } catch (UnknownHostException e) {
      throw new AssertionError();
    }

    IcmpV4RedirectPacket.Builder b
      = new IcmpV4RedirectPacket.Builder();
    b.gatewayInternetAddress(gatewayInternetAddress)
     .invokingPacket(
        IcmpV4Helper.makePacketForInvokingPacketField(ipv4b.build())
      );
    this.packet = b.build();
  }

  /**
   * @throws java.lang.Exception
   */
  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    logger.info(
      "########## " + IcmpV4RedirectPacketTest.class.getSimpleName() + " START ##########"
    );
  }

  /**
   * @throws java.lang.Exception
   */
  @AfterClass
  public static void tearDownAfterClass() throws Exception {
  }

  /**
   * @throws java.lang.Exception
   */
  @Before
  public void setUp() throws Exception {
  }

  /**
   * @throws java.lang.Exception
   */
  @After
  public void tearDown() throws Exception {
    logger.info(
      "=================================================="
    );
  }

  /**
   * {@link org.pcap4j.packet.IcmpV4RedirectPacket#getBuilder()} のためのテスト・メソッド。
   */
  @Test
  public void testGetBuilder() {
    IcmpV4RedirectPacket.Builder builder = packet.getBuilder();
    assertEquals(packet, builder.build());
  }

  /**
   * {@link org.pcap4j.packet.IcmpV4RedirectPacket#newPacket(byte[])} のためのテスト・メソッド。
   */
  @Test
  public void testNewPacket() {
    IcmpV4RedirectPacket p = IcmpV4RedirectPacket.newPacket(packet.getRawData());
    assertEquals(packet, p);

    assertTrue(p.getHeader().getInvokingPacket().contains(IpV4Packet.class));
    assertTrue(p.getHeader().getInvokingPacket().contains(IcmpV4CommonPacket.class));
    assertTrue(p.getHeader().getInvokingPacket().contains(IcmpV4EchoPacket.class));
    assertTrue(p.getHeader().getInvokingPacket().contains(UnknownPacket.class));
    assertEquals(p.getHeader().getInvokingPacket().get(UnknownPacket.class).length(), 0);
    assertFalse(p.getHeader().getInvokingPacket().contains(IllegalPacket.class));
  }

  /**
   * {@link org.pcap4j.packet.IcmpV4RedirectPacket#getHeader()} のためのテスト・メソッド。
   */
  @Test
  public void testGetHeader() {
    IcmpV4RedirectHeader h = packet.getHeader();
    assertEquals(gatewayInternetAddress, h.getGatewayInternetAddress());
  }

  /**
   * {@link org.pcap4j.packet.AbstractPacket#length()} のためのテスト・メソッド。
   */
  @Test
  public void testLength() {
    assertEquals(packet.getRawData().length, packet.length());
  }

  /**
   * {@link org.pcap4j.packet.AbstractPacket#toString()} のためのテスト・メソッド。
   */
  @Test
  public void testToString() throws Exception {
    FileReader fr
      = new FileReader(
          "src/test/resources/" + getClass().getSimpleName() + ".log"
        );
    BufferedReader fbr = new BufferedReader(fr);
    StringReader sr = new StringReader(packet.toString());
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

  @Test
  public void testDump() throws Exception {
    String dumpFile = "test/" + this.getClass().getSimpleName() + ".pcap";

    IcmpV4CommonPacket.Builder icmpV4b = new IcmpV4CommonPacket.Builder();
    icmpV4b.type(IcmpV4Type.REDIRECT)
           .code(IcmpV4Code.REDIRECT_DATAGRAMS_FOR_HOST)
           .payloadBuilder(new SimpleBuilder(packet))
           .correctChecksumAtBuild(true);

    IpV4Packet.Builder ipv4b = new IpV4Packet.Builder();
    ipv4b.version(IpVersion.IPV4)
         .tos(IpV4Rfc791Tos.newInstance((byte)0))
         .identification((short)100)
         .ttl((byte)100)
         .protocol(IpNumber.ICMPV4)
         .srcAddr(
            (Inet4Address)InetAddress.getByAddress(
              new byte[] { (byte)192, (byte)0, (byte)2, (byte)1 }
            )
          )
        .dstAddr(
           (Inet4Address)InetAddress.getByAddress(
             new byte[] { (byte)192, (byte)0, (byte)2, (byte)2 }
           )
         )
        .payloadBuilder(icmpV4b)
        .correctChecksumAtBuild(true)
        .correctLengthAtBuild(true);

    EthernetPacket.Builder eb = new EthernetPacket.Builder();
    eb.dstAddr(MacAddress.getByName("fe:00:00:00:00:02"))
      .srcAddr(MacAddress.getByName("fe:00:00:00:00:01"))
      .type(EtherType.IPV4)
      .payloadBuilder(ipv4b)
      .paddingAtBuild(true);
    EthernetPacket ep = eb.build();

    PcapHandle handle = Pcaps.openDead(DataLinkType.EN10MB, 65536);
    PcapDumper dumper = handle.dumpOpen(dumpFile);
    dumper.dump(ep, 0, 0);
    dumper.close();
    handle.close();

    PcapHandle reader = Pcaps.openOffline(dumpFile);
    assertEquals(ep, reader.getNextPacket());
    reader.close();

    FileInputStream in1
      = new FileInputStream(
          "src/test/resources/" + getClass().getSimpleName() + ".pcap"
        );
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
  public void testWriteRead() throws Exception {
    String objFile = "test/" + this.getClass().getSimpleName() + ".obj";

    ObjectOutputStream oos
      = new ObjectOutputStream(
          new FileOutputStream(new File(objFile))
        );
    oos.writeObject(packet);
    oos.close();

    ObjectInputStream ois
      = new ObjectInputStream(new FileInputStream(new File(objFile)));
    assertEquals(packet, ois.readObject());
    ois.close();

    FileInputStream in1
      = new FileInputStream(
          "src/test/resources/" + getClass().getSimpleName() + ".obj"
        );
    FileInputStream in2 = new FileInputStream(objFile);

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
