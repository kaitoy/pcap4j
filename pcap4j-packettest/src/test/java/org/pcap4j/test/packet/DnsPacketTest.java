package org.pcap4j.test.packet;

import static org.junit.Assert.assertEquals;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.pcap4j.packet.DnsDomainName;
import org.pcap4j.packet.DnsDomainName.Builder;
import org.pcap4j.packet.DnsPacket;
import org.pcap4j.packet.DnsPacket.DnsHeader;
import org.pcap4j.packet.DnsQuestion;
import org.pcap4j.packet.DnsRDataA;
import org.pcap4j.packet.DnsRDataAaaa;
import org.pcap4j.packet.DnsRDataCName;
import org.pcap4j.packet.DnsRDataCaa;
import org.pcap4j.packet.DnsRDataHInfo;
import org.pcap4j.packet.DnsRDataMInfo;
import org.pcap4j.packet.DnsRDataMb;
import org.pcap4j.packet.DnsRDataMd;
import org.pcap4j.packet.DnsRDataMf;
import org.pcap4j.packet.DnsRDataMg;
import org.pcap4j.packet.DnsRDataMr;
import org.pcap4j.packet.DnsRDataMx;
import org.pcap4j.packet.DnsRDataNs;
import org.pcap4j.packet.DnsRDataNull;
import org.pcap4j.packet.DnsRDataPtr;
import org.pcap4j.packet.DnsRDataSoa;
import org.pcap4j.packet.DnsRDataTxt;
import org.pcap4j.packet.DnsRDataWks;
import org.pcap4j.packet.DnsResourceRecord;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.IpV6SimpleFlowLabel;
import org.pcap4j.packet.IpV6SimpleTrafficClass;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.SimpleBuilder;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.namednumber.DnsClass;
import org.pcap4j.packet.namednumber.DnsOpCode;
import org.pcap4j.packet.namednumber.DnsRCode;
import org.pcap4j.packet.namednumber.DnsResourceRecordType;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.UdpPort;
import org.pcap4j.util.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SuppressWarnings("javadoc")
public class DnsPacketTest extends AbstractPacketTest {

  private static final Logger logger = LoggerFactory.getLogger(DnsPacketTest.class);

  private final DnsPacket packet;
  private final short id;
  private final boolean response;
  private final DnsOpCode opCode;
  private final boolean authoritativeAnswer;
  private final boolean truncated;
  private final boolean recursionDesired;
  private final boolean recursionAvailable;
  private final boolean reserved;
  private final boolean authenticData;
  private final boolean checkingDisabled;
  private final DnsRCode rCode;
  private final short qdCount;
  private final short anCount;
  private final short nsCount;
  private final short arCount;
  private final List<DnsQuestion> questions;
  private final List<DnsResourceRecord> answers;
  private final List<DnsResourceRecord> authorities;
  private final List<DnsResourceRecord> additionalInfo;

  public DnsPacketTest() throws Exception {
    this.id = 12233;
    this.response = true;
    this.opCode = DnsOpCode.STATUS;
    this.authoritativeAnswer = false;
    this.truncated = false;
    this.recursionDesired = true;
    this.recursionAvailable = true;
    this.reserved = false;
    this.authenticData = true;
    this.checkingDisabled = false;
    this.rCode = DnsRCode.NOT_AUTH;
    this.qdCount = 1;
    this.anCount = 6;
    this.nsCount = 6;
    this.arCount = 9;
    this.questions = new ArrayList<DnsQuestion>();
    this.answers = new ArrayList<DnsResourceRecord>();
    this.authorities = new ArrayList<DnsResourceRecord>();
    this.additionalInfo = new ArrayList<DnsResourceRecord>();

    List<String> hogeDomain = new ArrayList<String>();
    hogeDomain.add("hoge");
    hogeDomain.add("co");
    hogeDomain.add("jp");

    List<String> www = new ArrayList<String>();
    www.add("www");

    List<String> fooDomain = new ArrayList<String>();
    fooDomain.add("foo");
    fooDomain.add("org");

    DnsQuestion question =
        new DnsQuestion.Builder()
            .qName(new Builder().labels(hogeDomain).build())
            .qType(DnsResourceRecordType.A)
            .qClass(DnsClass.IN)
            .build();
    questions.add(question);

    DnsResourceRecord aRR =
        new DnsResourceRecord.Builder()
            .name(new Builder().labels(hogeDomain).build())
            .dataType(DnsResourceRecordType.A)
            .dataClass(DnsClass.ANY)
            .ttl(123123)
            .rData(
                new DnsRDataA.Builder()
                    .address((Inet4Address) InetAddress.getByName("1.2.3.4"))
                    .addressPlainText(false)
                    .build())
            .correctLengthAtBuild(true)
            .build();
    answers.add(aRR);

    DnsResourceRecord aaaaRR =
        new DnsResourceRecord.Builder()
            .name(new Builder().labels(hogeDomain).build())
            .dataType(DnsResourceRecordType.AAAA)
            .dataClass(DnsClass.ANY)
            .ttl(123123)
            .rData(
                new DnsRDataAaaa.Builder()
                    .address((Inet6Address) InetAddress.getByName("2001:db8::3:2:1"))
                    .build())
            .correctLengthAtBuild(true)
            .build();
    answers.add(aaaaRR);

    DnsResourceRecord cnameRR =
        new DnsResourceRecord.Builder()
            .name(new Builder().labels(hogeDomain).build())
            .dataType(DnsResourceRecordType.CNAME)
            .dataClass(DnsClass.ANY)
            .ttl(123123)
            .rData(
                new DnsRDataCName.Builder()
                    .cName(new Builder().labels(www).pointer((short) 12).build())
                    .build())
            .correctLengthAtBuild(true)
            .build();
    answers.add(cnameRR);

    DnsResourceRecord hinfoRR =
        new DnsResourceRecord.Builder()
            .name(new Builder().labels(hogeDomain).build())
            .dataType(DnsResourceRecordType.HINFO)
            .dataClass(DnsClass.ANY)
            .ttl(123123)
            .rData(new DnsRDataHInfo.Builder().cpu("AWESOME CPU").os("Windows").build())
            .correctLengthAtBuild(true)
            .build();
    answers.add(hinfoRR);

    DnsResourceRecord mbRR =
        new DnsResourceRecord.Builder()
            .name(new Builder().labels(hogeDomain).build())
            .dataType(DnsResourceRecordType.MB)
            .dataClass(DnsClass.ANY)
            .ttl(123123)
            .rData(
                new DnsRDataMb.Builder()
                    .maDName(new Builder().labels(www).pointer((short) 12).build())
                    .build())
            .correctLengthAtBuild(true)
            .build();
    answers.add(mbRR);

    DnsResourceRecord aCaaRR =
        new DnsResourceRecord.Builder()
            .name(new Builder().labels(hogeDomain).build())
            .dataType(DnsResourceRecordType.CAA)
            .dataClass(DnsClass.ANY)
            .ttl(321321)
            .rData(
                new DnsRDataCaa.Builder()
                    .critical(true)
                    .reservedFlags((byte) 0x12)
                    .tag("issue")
                    .value("ca.local")
                    .build())
            .correctLengthAtBuild(true)
            .build();
    answers.add(aCaaRR);

    DnsResourceRecord mdRR =
        new DnsResourceRecord.Builder()
            .name(new Builder().labels(hogeDomain).build())
            .dataType(DnsResourceRecordType.MD)
            .dataClass(DnsClass.ANY)
            .ttl(321321)
            .rData(
                new DnsRDataMd.Builder()
                    .maDName(new Builder().labels(www).pointer((short) 12).build())
                    .build())
            .correctLengthAtBuild(true)
            .build();
    authorities.add(mdRR);

    DnsResourceRecord mfRR =
        new DnsResourceRecord.Builder()
            .name(new Builder().labels(hogeDomain).build())
            .dataType(DnsResourceRecordType.MF)
            .dataClass(DnsClass.ANY)
            .ttl(321321)
            .rData(
                new DnsRDataMf.Builder()
                    .maDName(new Builder().labels(www).pointer((short) 12).build())
                    .build())
            .correctLengthAtBuild(true)
            .build();
    authorities.add(mfRR);

    DnsResourceRecord mgRR =
        new DnsResourceRecord.Builder()
            .name(new Builder().labels(hogeDomain).build())
            .dataType(DnsResourceRecordType.MG)
            .dataClass(DnsClass.ANY)
            .ttl(321321)
            .rData(
                new DnsRDataMg.Builder()
                    .mgMName(new Builder().labels(www).pointer((short) 12).build())
                    .build())
            .correctLengthAtBuild(true)
            .build();
    authorities.add(mgRR);

    DnsResourceRecord minfoRR =
        new DnsResourceRecord.Builder()
            .name(new Builder().labels(hogeDomain).build())
            .dataType(DnsResourceRecordType.MINFO)
            .dataClass(DnsClass.ANY)
            .ttl(321321)
            .rData(
                new DnsRDataMInfo.Builder()
                    .eMailBx(new Builder().labels(hogeDomain).build())
                    .rMailBx(new Builder().labels(fooDomain).build())
                    .build())
            .correctLengthAtBuild(true)
            .build();
    authorities.add(minfoRR);

    DnsResourceRecord mrRR =
        new DnsResourceRecord.Builder()
            .name(new Builder().labels(hogeDomain).build())
            .dataType(DnsResourceRecordType.MR)
            .dataClass(DnsClass.ANY)
            .ttl(321321)
            .rData(
                new DnsRDataMr.Builder().newName(new Builder().labels(fooDomain).build()).build())
            .correctLengthAtBuild(true)
            .build();
    authorities.add(mrRR);

    DnsResourceRecord mxRR =
        new DnsResourceRecord.Builder()
            .name(new Builder().labels(hogeDomain).build())
            .dataType(DnsResourceRecordType.MX)
            .dataClass(DnsClass.ANY)
            .ttl(321321)
            .rData(
                new DnsRDataMx.Builder()
                    .preference((short) -11111)
                    .exchange(new Builder().labels(fooDomain).build())
                    .build())
            .correctLengthAtBuild(true)
            .build();
    authorities.add(mxRR);

    DnsResourceRecord nsRR =
        new DnsResourceRecord.Builder()
            .name(new Builder().labels(hogeDomain).build())
            .dataType(DnsResourceRecordType.NS)
            .dataClass(DnsClass.ANY)
            .ttl(321321)
            .rData(
                new DnsRDataNs.Builder().nsDName(new Builder().labels(fooDomain).build()).build())
            .correctLengthAtBuild(true)
            .build();
    additionalInfo.add(nsRR);

    DnsResourceRecord nullRR =
        new DnsResourceRecord.Builder()
            .name(new Builder().labels(hogeDomain).build())
            .dataType(DnsResourceRecordType.NULL)
            .dataClass(DnsClass.ANY)
            .ttl(123456)
            .rData(
                new DnsRDataNull.Builder().rawData(new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9}).build())
            .correctLengthAtBuild(true)
            .build();
    additionalInfo.add(nullRR);

    DnsResourceRecord ptrRR =
        new DnsResourceRecord.Builder()
            .name(new Builder().labels(hogeDomain).build())
            .dataType(DnsResourceRecordType.PTR)
            .dataClass(DnsClass.ANY)
            .ttl(321321)
            .rData(
                new DnsRDataPtr.Builder().ptrDName(new Builder().labels(fooDomain).build()).build())
            .correctLengthAtBuild(true)
            .build();
    additionalInfo.add(ptrRR);

    DnsResourceRecord soaRR =
        new DnsResourceRecord.Builder()
            .name(new Builder().labels(hogeDomain).build())
            .dataType(DnsResourceRecordType.SOA)
            .dataClass(DnsClass.ANY)
            .ttl(321321)
            .rData(
                new DnsRDataSoa.Builder()
                    .mName(new Builder().labels(hogeDomain).build())
                    .rName(new Builder().labels(fooDomain).build())
                    .serial(11111111)
                    .refresh(22222222)
                    .retry(33333333)
                    .expire(44444444)
                    .minimum(55555555)
                    .build())
            .correctLengthAtBuild(true)
            .build();
    additionalInfo.add(soaRR);

    List<String> txts = new ArrayList<String>();
    txts.add("Pen");
    txts.add("Pineapple");
    txts.add("Apple");
    txts.add("Pen");
    DnsResourceRecord txtRR =
        new DnsResourceRecord.Builder()
            .name(new Builder().labels(hogeDomain).build())
            .dataType(DnsResourceRecordType.TXT)
            .dataClass(DnsClass.ANY)
            .ttl(321321)
            .rData(new DnsRDataTxt.Builder().texts(txts).build())
            .correctLengthAtBuild(true)
            .build();
    additionalInfo.add(txtRR);

    DnsResourceRecord wksRR1 =
        new DnsResourceRecord.Builder()
            .name(new Builder().labels(hogeDomain).build())
            .dataType(DnsResourceRecordType.WKS)
            .dataClass(DnsClass.ANY)
            .ttl(321321)
            .rData(
                new DnsRDataWks.Builder()
                    .address((Inet4Address) InetAddress.getByName("4.3.2.1"))
                    .protocol(IpNumber.UDP)
                    .bitMap(new byte[] {0, 0, 0, 0, (byte) 0x81, 0, 0x10})
                    .build())
            .correctLengthAtBuild(true)
            .build();
    additionalInfo.add(wksRR1);

    List<Integer> ports = new ArrayList<Integer>();
    ports.add(20);
    ports.add(300);
    ports.add(4000);
    DnsResourceRecord wksRR2 =
        new DnsResourceRecord.Builder()
            .name(new Builder().labels(hogeDomain).build())
            .dataType(DnsResourceRecordType.WKS)
            .dataClass(DnsClass.ANY)
            .ttl(321321)
            .rData(
                new DnsRDataWks.Builder()
                    .address((Inet4Address) InetAddress.getByName("2.3.2.3"))
                    .protocol(IpNumber.TCP)
                    .portNumbers(ports)
                    .build())
            .correctLengthAtBuild(true)
            .build();
    additionalInfo.add(wksRR2);

    DnsResourceRecord aRRStr =
        new DnsResourceRecord.Builder()
            .name(new Builder().labels(hogeDomain).build())
            .dataType(DnsResourceRecordType.A)
            .dataClass(DnsClass.ANY)
            .ttl(123123)
            .rData(
                new DnsRDataA.Builder()
                    .address((Inet4Address) InetAddress.getByName("192.168.0.100"))
                    .addressPlainText(true)
                    .build())
            .correctLengthAtBuild(true)
            .build();
    additionalInfo.add(aRRStr);

    DnsResourceRecord optRR =
        new DnsResourceRecord.Builder()
            .name(DnsDomainName.ROOT_DOMAIN)
            .dataType(DnsResourceRecordType.OPT)
            .dataClass(DnsClass.ANY)
            .ttl(123123)
            .correctLengthAtBuild(true)
            .build();
    additionalInfo.add(optRR);

    this.packet =
        new DnsPacket.Builder()
            .id(id)
            .response(response)
            .opCode(opCode)
            .authoritativeAnswer(authoritativeAnswer)
            .truncated(truncated)
            .recursionDesired(recursionDesired)
            .recursionAvailable(recursionAvailable)
            .reserved(reserved)
            .authenticData(authenticData)
            .checkingDisabled(checkingDisabled)
            .rCode(rCode)
            .qdCount(qdCount)
            .anCount(anCount)
            .nsCount(nsCount)
            .arCount(arCount)
            .questions(questions)
            .answers(answers)
            .authorities(authorities)
            .additionalInfo(additionalInfo)
            .build();
  }

  @Override
  protected Packet getPacket() {
    return packet;
  }

  @Override
  protected Packet getWholePacket() {
    Inet6Address srcAddr;
    Inet6Address dstAddr;
    try {
      srcAddr = (Inet6Address) InetAddress.getByName("2001:db8::3:2:1");
      dstAddr = (Inet6Address) InetAddress.getByName("2001:db8::3:2:2");
    } catch (UnknownHostException e) {
      throw new AssertionError("Never get here.");
    }

    UdpPacket.Builder udpb =
        new UdpPacket.Builder()
            .dstPort(UdpPort.DOMAIN)
            .srcPort(UdpPort.getInstance((short) 32211))
            .srcAddr(srcAddr)
            .dstAddr(dstAddr)
            .correctChecksumAtBuild(true)
            .correctLengthAtBuild(true)
            .payloadBuilder(new SimpleBuilder(packet));

    IpV6Packet.Builder IpV6b =
        new IpV6Packet.Builder()
            .version(IpVersion.IPV6)
            .trafficClass(IpV6SimpleTrafficClass.newInstance((byte) 0x12))
            .flowLabel(IpV6SimpleFlowLabel.newInstance(0x12345))
            .nextHeader(IpNumber.UDP)
            .hopLimit((byte) 100)
            .srcAddr(srcAddr)
            .dstAddr(dstAddr)
            .payloadBuilder(udpb)
            .correctLengthAtBuild(true);

    EthernetPacket.Builder eb =
        new EthernetPacket.Builder()
            .dstAddr(MacAddress.getByName("fe:00:00:00:00:02"))
            .srcAddr(MacAddress.getByName("fe:00:00:00:00:01"))
            .type(EtherType.IPV6)
            .payloadBuilder(IpV6b)
            .paddingAtBuild(true);

    return eb.build();
  }

  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    logger.info("########## " + DnsPacketTest.class.getSimpleName() + " START ##########");
  }

  @AfterClass
  public static void tearDownAfterClass() throws Exception {
    logger.info("########## " + DnsPacketTest.class.getSimpleName() + " END ##########");
  }

  @Test
  public void testGetHeader() {
    DnsHeader h = packet.getHeader();
    assertEquals(id, h.getId());
    assertEquals(response, h.isResponse());
    assertEquals(opCode, h.getOpCode());
    assertEquals(authoritativeAnswer, h.isAuthoritativeAnswer());
    assertEquals(truncated, h.isTruncated());
    assertEquals(recursionDesired, h.isRecursionDesired());
    assertEquals(recursionAvailable, h.isRecursionAvailable());
    assertEquals(reserved, h.getReservedBit());
    assertEquals(authenticData, h.isAuthenticData());
    assertEquals(checkingDisabled, h.isCheckingDisabled());
    assertEquals(rCode, h.getrCode());
    assertEquals(qdCount, h.getQdCount());
    assertEquals(anCount, h.getAnCount());
    assertEquals(nsCount, h.getNsCount());
    assertEquals(arCount, h.getArCount());

    assertEquals(questions.size(), h.getQuestions().size());
    for (int i = 0; i < questions.size(); i++) {
      assertEquals(questions.get(i), h.getQuestions().get(i));
    }

    assertEquals(answers.size(), h.getAnswers().size());
    for (int i = 0; i < answers.size(); i++) {
      assertEquals(answers.get(i), h.getAnswers().get(i));
    }

    assertEquals(authorities.size(), h.getAuthorities().size());
    for (int i = 0; i < authorities.size(); i++) {
      assertEquals(authorities.get(i), h.getAuthorities().get(i));
    }

    assertEquals(additionalInfo.size(), h.getAdditionalInfo().size());
    for (int i = 0; i < additionalInfo.size(); i++) {
      assertEquals(additionalInfo.get(i), h.getAdditionalInfo().get(i));
    }

    DnsPacket.Builder bldr = packet.getBuilder();
    DnsPacket p;

    bldr.qdCount((short) 0);
    bldr.anCount((short) 0);
    bldr.nsCount((short) 0);
    bldr.arCount((short) 0);
    p = bldr.build();
    assertEquals((short) 0, (short) p.getHeader().getQdCountAsInt());
    assertEquals((short) 0, (short) p.getHeader().getAnCountAsInt());
    assertEquals((short) 0, (short) p.getHeader().getNsCountAsInt());
    assertEquals((short) 0, (short) p.getHeader().getArCountAsInt());

    bldr.qdCount((short) 12345);
    bldr.anCount((short) 12345);
    bldr.nsCount((short) 12345);
    bldr.arCount((short) 12345);
    p = bldr.build();
    assertEquals((short) 12345, (short) p.getHeader().getQdCountAsInt());
    assertEquals((short) 12345, (short) p.getHeader().getAnCountAsInt());
    assertEquals((short) 12345, (short) p.getHeader().getNsCountAsInt());
    assertEquals((short) 12345, (short) p.getHeader().getArCountAsInt());

    bldr.qdCount((short) 32767);
    bldr.anCount((short) 32767);
    bldr.nsCount((short) 32767);
    bldr.arCount((short) 32767);
    p = bldr.build();
    assertEquals((short) 32767, (short) p.getHeader().getQdCountAsInt());
    assertEquals((short) 32767, (short) p.getHeader().getAnCountAsInt());
    assertEquals((short) 32767, (short) p.getHeader().getNsCountAsInt());
    assertEquals((short) 32767, (short) p.getHeader().getArCountAsInt());

    bldr.qdCount((short) -1);
    bldr.anCount((short) -1);
    bldr.nsCount((short) -1);
    bldr.arCount((short) -1);
    p = bldr.build();
    assertEquals((short) -1, (short) p.getHeader().getQdCountAsInt());
    assertEquals((short) -1, (short) p.getHeader().getAnCountAsInt());
    assertEquals((short) -1, (short) p.getHeader().getNsCountAsInt());
    assertEquals((short) -1, (short) p.getHeader().getArCountAsInt());

    bldr.qdCount((short) -32768);
    bldr.anCount((short) -32768);
    bldr.nsCount((short) -32768);
    bldr.arCount((short) -32768);
    p = bldr.build();
    assertEquals((short) -32768, (short) p.getHeader().getQdCountAsInt());
    assertEquals((short) -32768, (short) p.getHeader().getAnCountAsInt());
    assertEquals((short) -32768, (short) p.getHeader().getNsCountAsInt());
    assertEquals((short) -32768, (short) p.getHeader().getArCountAsInt());
  }

  @Test
  public void testNewPacket() {
    try {
      DnsPacket p = DnsPacket.newPacket(packet.getRawData(), 0, packet.getRawData().length);
      assertEquals(packet, p);
    } catch (IllegalRawDataException e) {
      throw new AssertionError(e);
    }
  }

  @Override
  @Test
  public void testToString() {
    for (DnsResourceRecord r : packet.getHeader().getAnswers()) {
      logger.info(r.toString());
    }
    for (DnsResourceRecord r : packet.getHeader().getAuthorities()) {
      logger.info(r.toString());
    }
    for (DnsResourceRecord r : packet.getHeader().getAdditionalInfo()) {
      logger.info(r.toString());
    }
  }
}
