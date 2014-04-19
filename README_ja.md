[English](https://github.com/kaitoy/pcap4j)

<img alt="Pcap4J" title="Pcap4J" src="https://github.com/kaitoy/pcap4j/raw/master/www/images/pcap4jlogo.png" height="217" width="667" />

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

Pcap4J 1.1.0 (Maven Central Repositoryにある最新バージョン)

* ソースなし: [pcap4j-distribution-1.1.0-bin.zip](http://search.maven.org/remotecontent?filepath=org/pcap4j/pcap4j-distribution/1.1.0/pcap4j-distribution-1.1.0-bin.zip)
* ソース入り: [pcap4j-distribution-1.1.0-src.zip](http://search.maven.org/remotecontent?filepath=org/pcap4j/pcap4j-distribution/1.1.0/pcap4j-distribution-1.1.0-src.zip)

開発経緯
--------

SNMPネットワークシミュレータをJavaで作っていて、ICMPをいじるためにパケットキャプチャをしたくなったが、
Raw Socketやデータリンクアクセスを使って自力でやるのは大変そうなので [pcap](http://ja.wikipedia.org/wiki/Pcap)を使うことに。

pcapの実装は、UNIX系にはlibpcap、WindowsにはWinPcapがあるが、いずれもネイティブライブラリ。
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
* Ethernet、IEEE802.1Q、ARP、IPv4(RFC791、RFC1349)、IPv6(RFC2460)、ICMPv4(RFC792)、ICMPv6(RFC4443, RFC4861)、TCP(RFC793)、UDPに対応。
* 各ビルトインパケットクラスはシリアライズに対応。スレッドセーフ(実質的に不変)。
* ライブラリをいじらずに、対応プロトコルをユーザが追加できる。
* pcapのダンプファイル(Wiresharkのcapture fileなど)の読み込み、書き込み。

対応OS
------

x86プロセッサ上の以下のOSで動作することを確認した。

* Windows: XP, Vista, 7, 2003 R2, 2008, 2008 R2, and 2012
* Linux
 * RHEL: 5 and 6
 * CentOS: 5
 * Ubuntu: 13
* UNIX
 * Solaris: 10
 * FreeBSD: 10

また、tomuteさんからMac OS Xで動いたとの[報告](http://tomute.hateblo.jp/entry/2013/01/27/003209)が。ありがとうございます。

他のアーキテクチャ/OSでも、JNAとlibpcapがサポートしていれば動く、と願う(FreeBSDはだめそう)。

使い方
------

最新のJavaDocは[こちら](http://kaitoy.github.com/pcap4j/javadoc/latest/en)。
各バージョンのJavaDocは[Maven Central Repository](http://search.maven.org/#search|ga|1|g%3A%22org.pcap4j%22)からダウンロードできる。
0.9.13のJavaDocは[こちら](http://kaitoy.github.com/pcap4j/javadoc/0.9.13/en)。

他にも、以下のリンクから情報を得られる。

* [libpcapのドキュメント](http://www.tcpdump.org/pcap.html)
* [WinPcapのドキュメント](http://www.winpcap.org/docs/default.htm)
* [pcap API と Pcap4j API の対応](/www/api_mappings.md)
* [Learn About Packet](/www/Packet.md)
* [Learn About Packet Factory](/www/PacketFactory.md)
* [テストクラス](https://github.com/kaitoy/pcap4j/tree/master/pcap4j-packettest/src/test/java/org/pcap4j/packet)
* [サンプルクラス](https://github.com/kaitoy/pcap4j/tree/master/pcap4j-sample/src/main/java/org/pcap4j/sample)
* [サポートプロトコル追加方法](/www/HowToAddProtocolSupport.md)

1.1.0以前のはJ2SE 5.0以降で動く。1.2.0以降のはJ2SE 6.0以降で動く。管理者権限で実行する必要がある。
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
* Mac OS X
 * サーチパス: OSに設定された共有ライブラリのサーチパス。例えば環境変数`DYLD_LIBRARY_PATH`に含まれるパス。
 * ファイル名: libpcap.dylib
 
カスタマイズのために、以下のJavaのシステムプロパティが使える。

* jna.library.path: サーチパスを指定する。
* org.pcap4j.core.pcapLibName: ライブラリへのフルパスを指定する。


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
            <artifactId>pcap4j-core</artifactId>
            <version>1.1.0</version>
          </dependency>
          <dependency>
            <groupId>org.pcap4j</groupId>
            <artifactId>pcap4j-packetfactory-static</artifactId>
            <version>1.1.0</version>
          </dependency>
             ...
        </dependencies>
        ...
      </project>


実行例
------

* [org.pcap4j.sample.Loop](/www/sample_Loop_ja.md)
* [org.pcap4j.sample.SendArpRequest](/www/sample_SendArpRequest_ja.md)


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
  「一般」の「既存プロジェクトをワークスペースへ」で 3. でダウンロードしたレポジトリ内の全プロジェクトをインポートする。
6. ビルド<br>
   EclipseのGUIのプロジェクト・エクスプローラーで、Pcap4Jの親プロジェクトを右クリックして、
   [実行]＞[Maven package] か [実行]＞[Maven install] を実行する。
   unit testを通すためにはAdministrator/root権限が必要。

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
  unit testを通すためにはAdministrator/root権限が必要。

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

Pcap4J を使ったSNMPネットワークシミュレータ、SNeO。Githubに公開しました: https://github.com/kaitoy/sneo
