[English](https://github.com/kaitoy/pcap4j)

<img alt="Pcap4J" title="Pcap4J" src="https://github.com/kaitoy/pcap4j/tree/master/www/images/pcap4jlogo.png" style="width: 667px; height: 217px;" />

Pcap4J
======

パケットをキャプチャ・作成・送信するためのJavaライブラリ。
ネイティブのパケットキャプチャライブラリである[libpcap](http://www.tcpdump.org/)
または[WinPcap](http://www.winpcap.org/)を[JNA](https://github.com/twall/jna)を
使ってラッピングして、JavaらしいAPIに仕上げたもの。

ダウンロード
------------

Maven Central Repositoryからダウンロードできるようになりました。

Pcap4J 0.9.13 (このページから配布する最後のバージョン)

* [pcap4j.jar](https://github.com/downloads/kaitoy/pcap4j/pcap4j.jar)

Pcap4J 0.9.14 (Maven Central Repositoryにある最新バージョン)

* [pcap4j-0.9.14.jar](http://search.maven.org/remotecontent?filepath=org/pcap4j/pcap4j/0.9.14/pcap4j-0.9.14.jar)

開発経緯
--------

SNMPネットワークシミュレータをJavaで作っていて、ICMPをいじるためにパケットキャプチャをしたくなったが、
Raw Socketやデータリンクアクセスを使って自力でやるのは大変そうなので pcap APIを使うことに。

pcap APIの実装は、UNIX系にはlibpcap、WindowsにはWinPcapがあるが、いずれもネイティブライブラリ。
これらのJavaラッパは[jpcap](http://jpcap.sourceforge.net/)や[jNetPcap](http://jnetpcap.com/)が既にあるが、
これらはパケットキャプチャに特化していて、パケット作成・送信がしにくいような気がした。

[Jpcap](http://netresearch.ics.uci.edu/kfujii/Jpcap/doc/)はパケット作成・送信もやりやすいけど、
ICMPのキャプチャ周りにバグがあって使えなかった。結構前から開発が止まっているようだし。
ということで自作した。

機能
----

* ネットワークインターフェースからパケットをキャプチャし、Javaのオブジェクトに変換する。
* パケットオブジェクトにアクセスしてパケットのフィールドを取得できる。
* 手動でパケットオブジェクトを組み立てることもできる。
* パケットオブジェクトを現実のパケットに変換してネットワークに送信できる。
* Ethernet、IEEE802.1Q、ARP、IPv4(RFC791、RFC1349)、IPv6(RFC2460)、ICMPv4(RFC792)、TCP(RFC793)、UDPに対応。
* 各パケットクラスはシリアライズに対応。スレッドセーフ(実質的に不変)。
* ライブラリをいじらずに、対応プロトコルをユーザが追加できる。
* pcap APIのダンプファイル(Wiresharkのcapture fileなど)の読み込み、書き込み。

対応OS
------

x86プロセッサ上の以下のOSで動作することを確認した。

* Windows: XP, Vista, 7, 2003 R2, 2008, 2008 R2, and 2012
* Linux
 * RHEL: 5 and 6
 * CentOS: 5
* UNIX
 * Solaris: 10

また、tomuteさんからMac OS Xで動いたとの[報告](http://tomute.hateblo.jp/entry/2013/01/27/003209)が。ありがとうございます。

他のアーキテクチャ/OSでも、JNAとlibpcapがサポートしていれば動く、と願う(FreeBSDはだめそう)。

使い方
------

最新のJavaDocは[こちら](http://kaitoy.github.com/pcap4j/javadoc/latest/en)。
各バージョンのJavaDocは[Maven Central Repository](http://search.maven.org/#search|ga|1|a%3A%22pcap4j%22)からダウンロードできる。
0.9.13のJavaDocは[こちら](http://kaitoy.github.com/pcap4j/javadoc/0.9.13/en)。

他にも、以下のリンクから情報を得られる。

* [libpcapのドキュメント](http://www.tcpdump.org/pcap.html)
* [WinPcapのドキュメント](http://www.winpcap.org/docs/default.htm)
* [Learn About Packet](/www/Packet.md)
* [Learn About Packet Factory](/www/PacketFactory.md)
* [テストクラス](https://github.com/kaitoy/pcap4j/tree/master/src/test/java/org/pcap4j/packet)
* [サンプルクラス](https://github.com/kaitoy/pcap4j/tree/master/src/main/java/org/pcap4j/sample)

J2SE 5.0以降で動く。
UNIX系ならlibpcap (多分)0.9.3以降、WindowsならWinPcap (多分)3.0以降がインストールされている必要がある。
jna、slf4j-api(と適当なロガー実装モジュール)もクラスパスに含める必要がある。

動作確認に使っているバージョンは以下。

* libpcap 1.1.1
* WinPcap 4.1.2
* jna 3.5.2
* slf4j-api 1.6.4
* logback-core 1.0.1
* logback-classic 1.0.1


#### pcapライブラリのロードについて ####
デフォルトでは下記の条件でpcapライブラリを検索し、ロードする。

* Windows
 * サーチパス: 環境変数`PATH`に含まれるパス。
 * ファイル名: wpcap.dll
* Linux/UNIX
 * サーチパス: OSに設定された共有ライブラリのサーチパス。例えば環境変数`LD_LIBRARY_PATH`に含まれるパス。
 * ファイル名: libpcap.so

カスタマイズのために、以下のJavaのシステムプロパティが使える。

* jna.library.path: サーチパスを指定する。
* org.pcap4j.core.pcapLibName: ライブラリへのフルパスを指定する。


#### pcap API と Pcap4j API の対応 ####
<table border="1">
  <tr align=center>
    <td>pcap API</td>
    <td>Pcap4j API</td>
  </tr>
  <tr>
    <td>int pcap_findalldevs(pcap_if_t **, char *)</td>
    <td>static List&lt;PcapNetworkInterface&gt; org.pcap4j.core.Pcaps.findAllDevs()</td>
  </tr>
  <tr>
    <td>void pcap_freealldevs(pcap_if_t *)</td>
    <td>内部的mappingのみ</td>
  </tr>
  <tr>
    <td>char *pcap_lookupdev(char *)</td>
    <td>static String org.pcap4j.core.Pcaps.lookupDev()</td>
  </tr>
  <tr>
    <td>pcap_t *pcap_open_live(const char *, int, int, int, char *)</td>
    <td>PcapHandle org.pcap4j.core.PcapNetworkInterface.openLive(int, PromiscuousMode, int)</td>
  </tr>
  <tr>
    <td>pcap_t *pcap_open_dead(int, int)</td>
    <td>static PcapHandle org.pcap4j.core.Pcaps.openDead(DataLinkType, int)</td>
  </tr>
  <tr>
    <td>pcap_t *pcap_open_offline(const char *, char *)</td>
    <td>static PcapHandle org.pcap4j.core.Pcaps.openOffline(String)</td>
  </tr>
  <tr>
    <td>pcap_dumper_t *pcap_dump_open(pcap_t *, const char *)</td>
    <td>PcapDumper org.pcap4j.core.PcapHandle.dumpOpen(String)</td>
  </tr>
  <tr>
    <td rowspan="2">void pcap_dump(u_char *, const struct pcap_pkthdr *, const u_char *)</td>
    <td>void org.pcap4j.core.PcapDumper.dump(Packet, long, int)</td>
  </tr>
  <tr>
    <td>void org.pcap4j.core.PcapDumper.dump(Packet)</td>
  </tr>
  <tr>
    <td>void pcap_dump_close(pcap_dumper_t *)</td>
    <td>void org.pcap4j.core.PcapDumper.close()</td>
  </tr>
  <tr>
    <td>u_char *pcap_next(pcap_t *, struct pcap_pkthdr *)</td>
    <td>Packet org.pcap4j.core.PcapHandle.getNextPacket()</td>
  </tr>
  <tr>
    <td>int pcap_next_ex(pcap_t *, struct pcap_pkthdr **, const u_char **)</td>
    <td>Packet org.pcap4j.core.PcapHandle.getNextPacketEx()</td>
  </tr>
  <tr>
    <td rowspan="3">int pcap_loop(pcap_t *, int, pcap_handler, u_char *)</td>
    <td>void org.pcap4j.core.PcapHandle.loop(int, PacketListener)</td>
  </tr>
  <tr>
    <td>void org.pcap4j.core.PcapHandle.loop(int, PacketListener, Executor)</td>
  </tr>
  <tr>
    <td>void org.pcap4j.core.PcapHandle.loop(int, PcapDumper)</td>
  </tr>
  <tr>
    <td>void pcap_breakloop(pcap_t *)</td>
    <td>void org.pcap4j.core.PcapHandle.breakLoop()</td>
  </tr>
  <tr>
    <td>int pcap_compile(pcap_t *, struct bpf_program *, char *, int, bpf_u_int32)</td>
    <td>内部的mappingのみ</td>
  </tr>
  <tr>
    <td rowspan="2">int pcap_setfilter(pcap_t *, struct bpf_program *)</td>
    <td>void org.pcap4j.core.PcapHandle.setFilter(String, BpfCompileMode, Inet4Address)</td>
  </tr>
  <tr>
    <td>void org.pcap4j.core.PcapHandle.setFilter(String, BpfCompileMode)</td>
  </tr>
  <tr>
    <td>void pcap_freecode(struct bpf_program *)</td>
    <td>内部的mappingのみ</td>
  </tr>
  <tr>
    <td>int pcap_sendpacket(pcap_t *, const u_char *, int)</td>
    <td>void org.pcap4j.core.PcapHandle.sendPacket(Packet)</td>
  </tr>
  <tr>
    <td>void pcap_close(pcap_t *)</td>
    <td>void org.pcap4j.core.PcapHandle.close()</td>
  </tr>
  <tr>
    <td>int pcap_datalink(pcap_t *)</td>
    <td>内部的mappingのみ</td>
  </tr>
  <tr>
    <td>char *pcap_geterr(pcap_t *)</td>
    <td>String org.pcap4j.core.PcapHandle.getError()</td>
  </tr>
  <tr>
    <td>char *pcap_strerror(int)</td>
    <td>内部的mappingのみ</td>
  </tr>
</table>


#### Mavenプロジェクトでの使用方法 ####
pom.xmlに以下のような記述を追加する。

      <project xmlns="http://maven.apache.org/POM/4.0.0"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
                            http://maven.apache.org/xsd/maven-4.0.0.xsd">
        ...
        <dependencies>
          <dependency>
            <groupId>org.pcap4j</groupId>
            <artifactId>pcap4j</artifactId>
            <version>0.9.14</version>
          </dependency>
             ...
        </dependencies>
        ...
      </project>

サンプル
--------

* [org.pcap4j.sample.Loop](https://github.com/kaitoy/pcap4j/tree/master/src/main/java/org/pcap4j/sample/Loop.java)<br>
  パケットをキャプチャーしてダンプするサンプル。以下はLinuxでeth2からICMPパケットを2つキャプチャーした実行例。


        [root@localhost Desktop]# java -cp pcap4j.jar:jna-3.3.0.jar:slf4j-api-1.6.4.jar -Dorg.pcap4j.sample.Loop.count=2 org.pcap4j.sample.Loop icmp
        org.pcap4j.sample.Loop.count: 2
        org.pcap4j.sample.Loop.readTimeout: 10
        org.pcap4j.sample.Loop.maxCapLen: 65536


        SLF4J: Failed to load class "org.slf4j.impl.StaticLoggerBinder".
        SLF4J: Defaulting to no-operation (NOP) logger implementation
        SLF4J: See http://www.slf4j.org/codes.html#StaticLoggerBinder for further details.
        NIF[0]: eth0
              : description: null
              : address: /192.168.209.128
        NIF[1]: eth1
              : description: null
              : address: /192.168.76.128
        NIF[2]: eth2
              : description: null
              : address: /192.168.2.109
        NIF[3]: any
              : description: Pseudo-device that captures on all interfaces
        NIF[4]: lo
              : description: null
              : address: /127.0.0.1

        Select a device number to capture packets, or enter 'q' to quit > 2
        eth2(null)
        2012-10-05 03:48:51.881454
        [Ethernet Header (14 bytes)]
          Destination address: 00:0c:29:02:65:62
          Source address: 04:7d:7b:4c:2f:0a
          Type: 0x0800(IPv4)
        [IPv4 Header (20 bytes)]
          Version: 4(IPv4)
          IHL: 5 (20 [bytes])
          TOS: [precedence: 0(Routine)] [tos: 0(Default)] [mbz: 0]
          Total length: 60 [bytes]
          Identification: 3340
          Flags: (Reserved, Don't Fragment, More Fragment) = (false, false, false)
          Flagment offset: 0 (0 [bytes])
          TTL: 128
          Protocol: 1(ICMPv4)
          Header checksum: 0xa792
          Source address: /192.168.2.101
          Destination address: /192.168.2.109
        [ICMP Common Header (4 bytes)]
          Type: 8(Echo)
          Code: 0(No Code)
          Checksum: 0x4c53
        [ICMPv4 Echo Header (4 bytes)]
          Identifier: 256
          SequenceNumber: 9
        [data (32 bytes)]
          Hex stream: 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 61 62 63 64 65 66 67 68 69

        2012-10-05 03:48:51.979233
        [Ethernet Header (14 bytes)]
          Destination address: 04:7d:7b:4c:2f:0a
          Source address: 00:0c:29:02:65:62
          Type: 0x0800(IPv4)
        [IPv4 Header (20 bytes)]
          Version: 4(IPv4)
          IHL: 5 (20 [bytes])
          TOS: [precedence: 0(Routine)] [tos: 0(Default)] [mbz: 0]
          Total length: 60 [bytes]
          Identification: 19161
          Flags: (Reserved, Don't Fragment, More Fragment) = (false, false, false)
          Flagment offset: 0 (0 [bytes])
          TTL: 64
          Protocol: 1(ICMPv4)
          Header checksum: 0xa9c5
          Source address: /192.168.2.109
          Destination address: /192.168.2.101
        [ICMP Common Header (4 bytes)]
          Type: 0(Echo Reply)
          Code: 0(No Code)
          Checksum: 0x5453
        [ICMPv4 Echo Reply Header (4 bytes)]
          Identifier: 256
          SequenceNumber: 9
        [data (32 bytes)]
          Hex stream: 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 61 62 63 64 65 66 67 68 69


* [org.pcap4j.sample.SendArpRequest](https://github.com/kaitoy/pcap4j/tree/master/src/main/java/org/pcap4j/sample/SendArpRequest.java)<br>
  ARPリクエストを送信してIPアドレスをMACアドレスに解決するサンプル。以下はLinuxで192.168.209.1を解決した実行例。


        [root@localhost Desktop]# java -cp pcap4j.jar:jna-3.3.0.jar:slf4j-api-1.6.4.jar org.pcap4j.sample.SendArpRequest 192.168.209.1
        org.pcap4j.sample.SendArpRequest.count: 1
        org.pcap4j.sample.SendArpRequest.readTimeout: 10
        org.pcap4j.sample.SendArpRequest.maxCapLen: 65536


        SLF4J: Failed to load class "org.slf4j.impl.StaticLoggerBinder".
        SLF4J: Defaulting to no-operation (NOP) logger implementation
        SLF4J: See http://www.slf4j.org/codes.html#StaticLoggerBinder for further details.
        NIF[0]: eth0
              : description: null
              : address: /192.168.209.128
        NIF[1]: eth1
              : description: null
              : address: /192.168.76.128
        NIF[2]: eth2
              : description: null
              : address: /192.168.2.109
        NIF[3]: any
              : description: Pseudo-device that captures on all interfaces
        NIF[4]: lo
              : description: null
              : address: /127.0.0.1

        Select a device number to capture packets, or enter 'q' to quit > 0
        eth0(null)
        [Ethernet Header (14 bytes)]
          Destination address: ff:ff:ff:ff:ff:ff
          Source address: fe:00:01:02:03:04
          Type: 0x0806(ARP)
        [ARP Header (28 bytes)]
          Hardware type: 1(Ethernet(10Mb))
          Protocol type: 0x0800(IPv4)
          Hardware length: 6 [bytes]
          Protocol length: 4 [bytes]
          Operation: 1(REQUEST)
          Source hardware address: fe:00:01:02:03:04
          Source protocol address: /192.0.2.100
          Destination hardware address: ff:ff:ff:ff:ff:ff
          Destination protocol address: /192.168.209.1
        [Ethernet Pad (18 bytes)]
          Hex stream: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

        [Ethernet Header (14 bytes)]
          Destination address: fe:00:01:02:03:04
          Source address: 00:50:56:c0:00:08
          Type: 0x0806(ARP)
        [ARP Header (28 bytes)]
          Hardware type: 1(Ethernet(10Mb))
          Protocol type: 0x0800(IPv4)
          Hardware length: 6 [bytes]
          Protocol length: 4 [bytes]
          Operation: 2(REPLY)
          Source hardware address: 00:50:56:c0:00:08
          Source protocol address: /192.168.209.1
          Destination hardware address: fe:00:01:02:03:04
          Destination protocol address: /192.0.2.100
        [Ethernet Pad (18 bytes)]
          Hex stream: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

        192.168.209.1 was resolved to 00:50:56:c0:00:08

ビルド
------
開発に使っている環境は以下。

* [Eclipse](http://www.eclipse.org/) Java EE IDE for Web Developers Indigo Service Release 1([Pleiades](http://mergedoc.sourceforge.jp/) All in One 3.7.1.v20110924)
* [M2E - Maven Integration for Eclipse](http://eclipse.org/m2e/download/) 1.0.100.20110804-1717
* [Apache Maven](http://maven.apache.org/) 3.0.5

Eclipseからのビルド手順は以下。

0. WinPcap/libpcapインストール<br>
  ビルド時に実行されるunit testで必要なので。
1. Eclipseインストール<br>
  ダウンロードして解凍するだけ。
2. M2Eインストール<br>
   EclipseのGUIで、[ヘルプ]＞[新規ソフトウェアのインストール] を開き、
   「作業対象」に http://download.eclipse.org/technology/m2e/releases を入力してEnter。
   m2e - Eclipse用のMaven統合をチェックして「次へ」。
   使用条件の条項に同意しますにチェックして「完了」。
   m2eのインストールが完了したらEclipseを再起動。
3. Gitをインストール<br>
   [Git](http://git-scm.com/downloads)をダウンロードしてインストールする。
   Gitのインストールはビルドに必須ではないので、このステップはスキップしてもよい。
4. Pcap4Jのレポジトリのダウンロード<br>
   `git clone git@github.com:kaitoy/pcap4j.git` を実行する。
   ステップ3をスキップした場合は、[zip](https://github.com/kaitoy/pcap4j/zipball/master)でダウンロードして展開する。
5. プロジェクトのインポート<br>
  EclipseのGUIで、[ファイル]＞[インポート] を開き、
  「一般」の「既存プロジェクトをワークスペースへ」で 3. でダウンロードしたレポジトリ内のプロジェクトをインポートする。
6. ビルド<br>
   EclipseのGUIのプロジェクト・エクスプローラーで、Pcap4Jのプロジェクトを右クリックして、
   [実行]＞[Maven package] か [実行]＞[Maven install] を実行する。

因みに、M2Eは旧[m2eclipse](http://m2eclipse.sonatype.org/)。
m2eclipseでビルドしたい場合は、ステップ2をスキップして、ステップ4でMavenプロジェクトの方をインポートすればよい。

Mavenコマンドを直接実行するビルド手順は以下。

0. WinPcap/libpcapインストール<br>
  ビルド時に実行されるunit testで必要なので。
1. JDK1.5+インストール<br>
  JAVA_HOMEを設定する。
2. Mavenインストール<br>
  新しめのがいいかも。PATHを設定する。
3. Gitをインストール<br>
   [Git](http://git-scm.com/downloads)をダウンロードしてインストールする。
   Gitのインストールはビルドに必須ではないので、このステップはスキップしてもよい。
4. Pcap4Jのレポジトリのダウンロード<br>
   `git clone git@github.com:kaitoy/pcap4j.git` を実行する。
   ステップ3をスキップした場合は、[zip](https://github.com/kaitoy/pcap4j/zipball/master)でダウンロードして展開する。
5. ビルド<br>
  プロジェクトのルートディレクトリ(ステップ4でできたディレクトリ内のpom.xmlのあるところ)に`cd`して、`mvn install` を実行する。

ライセンス
----------

Pcap4J is distributed under the MIT license.

    Copyright (c) 2011-2013 Kaito Yamada
    All rights reserved.

    Permission is hereby granted, free of charge, to any person obtaining a copy of
    this software and associated documentation files (the "Software"), to deal in the Software without restriction,
    including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
    and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
    subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
    NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
    WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

    以下に定める条件に従い、本ソフトウェアおよび関連文書のファイル（以下「ソフトウェア」）の複製を取得するすべての人に対し、
    ソフトウェアを無制限に扱うことを無償で許可します。これには、ソフトウェアの複製を使用、複写、変更、結合、掲載、頒布、サブライセンス、
    および/または販売する権利、およびソフトウェアを提供する相手に同じことを許可する権利も無制限に含まれます。
    上記の著作権表示および本許諾表示を、ソフトウェアのすべての複製または重要な部分に記載するものとします。

    ソフトウェアは「現状のまま」で、明示であるか暗黙であるかを問わず、何らの保証もなく提供されます。
    ここでいう保証とは、商品性、特定の目的への適合性、および権利非侵害についての保証も含みますが、それに限定されるものではありません。
    作者または著作権者は、契約行為、不法行為、またはそれ以外であろうと、ソフトウェアに起因または関連し、
    あるいはソフトウェアの使用またはその他の扱いによって生じる一切の請求、損害、その他の義務について何らの責任も負わないものとします。


おまけ
------

Pcap4J 0.9.14 を使ったSNMPネットワークシミュレータ、SNeO。
とりあえず置いておくだけ。
商用でもなんでも無料で使用可。コピーも再配布も可。

SNeO 1.0.12

* [sneo.jar](http://www.pcap4j.org/artifacts/sneo.jar)
