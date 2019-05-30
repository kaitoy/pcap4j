[English](https://github.com/kaitoy/pcap4j)

<img alt="Pcap4J" title="Pcap4J" src="https://github.com/kaitoy/pcap4j/raw/v1/www/images/logos/pcap4j-logo-color.png" width="70%" style="margin: 0px auto; display: block;" />

[ロゴ](https://github.com/kaitoy/pcap4j/blob/v1/www/logos.md)

[![Slack](http://pcap4j-slackin.herokuapp.com/badge.svg)](https://pcap4j-slackin.herokuapp.com/)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/org.pcap4j/pcap4j-distribution/badge.svg)](https://maven-badges.herokuapp.com/maven-central/org.pcap4j/pcap4j-distribution)

[![Build Status](https://travis-ci.org/kaitoy/pcap4j.svg?branch=v1)](https://travis-ci.org/kaitoy/pcap4j)
[![CircleCI](https://circleci.com/gh/kaitoy/pcap4j/tree/v1.svg?style=svg)](https://circleci.com/gh/kaitoy/pcap4j/tree/v1)
[![Build status](https://ci.appveyor.com/api/projects/status/github/kaitoy/pcap4j?branch=v1&svg=true)](https://ci.appveyor.com/project/kaitoy/pcap4j/branch/v1)
[![Coverage Status](https://coveralls.io/repos/kaitoy/pcap4j/badge.svg)](https://coveralls.io/r/kaitoy/pcap4j)
[![Code Quality: Java](https://img.shields.io/lgtm/grade/java/g/kaitoy/pcap4j.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/kaitoy/pcap4j/context:java)
[![Total Alerts](https://img.shields.io/lgtm/alerts/g/kaitoy/pcap4j.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/kaitoy/pcap4j/alerts)

Pcap4J
======

パケットをキャプチャ・作成・送信するためのJavaライブラリ。
ネイティブのパケットキャプチャライブラリである[libpcap](http://www.tcpdump.org/)、
[WinPcap](http://www.winpcap.org/)、または[Npcap](https://github.com/nmap/npcap)を[JNA](https://github.com/twall/jna)を
使ってラッピングして、JavaらしいAPIに仕上げたもの。

目次
----

* [ダウンロード](#ダウンロード)
* [開発経緯](#開発経緯)
* [機能](#機能)
* [使い方](#使い方)
    * [システム要件](#システム要件)
        * [ライブラリ等の依存](#ライブラリ等の依存)
        * [プラットフォーム](#プラットフォーム)
        * [その他](#その他)
    * [ドキュメント](#ドキュメント)
    * [サンプル実行方法](#サンプル実行方法)
    * [Mavenプロジェクトでの使用方法](#mavenプロジェクトでの使用方法)
    * [ネイティブライブラリのロードについて](#ネイティブライブラリのロードについて)
        * [WinPcapかNpcapか](#WinPcapかNpcapか)
    * [Docker](#docker)
* [ビルド](#ビルド)
* [コードに貢献](#コードに貢献)
* [ライセンス](#ライセンス)
* [コンタクト](#コンタクト)

ダウンロード
------------

Maven Central Repositoryからダウンロードできる。

* Pcap4J 1.8.1
    * ソースなし: [pcap4j-distribution-1.8.1-bin.zip](http://search.maven.org/remotecontent?filepath=org/pcap4j/pcap4j-distribution/1.8.1/pcap4j-distribution-1.8.1-bin.zip)
    * ソース入り: [pcap4j-distribution-1.8.1-src.zip](http://search.maven.org/remotecontent?filepath=org/pcap4j/pcap4j-distribution/1.8.1/pcap4j-distribution-1.8.1-src.zip)
* スナップショットビルド
    * https://oss.sonatype.org/content/repositories/snapshots/org/pcap4j/pcap4j-distribution/

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
* 以下のプロトコルに対応。
    * Ethernet、Linux SLL、raw IP、PPP (RFC1661、RFC1662)、BSD (Mac OS X) loopback encapsulation、Radiotap
    * IEEE 802.11
        * Probe Request
    * LLC、SNAP
    * IEEE802.1Q
    * ARP
    * IPv4 (RFC791、RFC1349)、IPv6 (RFC2460)
    * ICMPv4 (RFC792)、ICMPv6 (RFC4443、RFC4861、RFC6275)
    * TCP (RFC793、RFC2018、draft-ietf-tcpm-1323bis-21)、UDP、SCTP (共通ヘッダのみ)
    * GTPv1 (GTP-UとGTP-Cのヘッダのみ)
    * DNS (RFC1035、RFC3596、RFC6844)
* 各ビルトインパケットクラスはシリアライズに対応。スレッドセーフ(実質的に不変)。
* ライブラリをいじらずに、対応プロトコルをユーザが追加できる。
* pcapのダンプファイル(Wiresharkのcapture fileなど)の読み込み、書き込み。

使い方
------

#### システム要件 ####

##### ライブラリ等の依存 #####
1.1.0以前のはJava 5.0以降で動く。1.2.0以降のはJava 6.0以降で動く。
UNIX系ならlibpcap 1.0.0以降、WindowsならWinPcap (多分)3.0以降かNpcapがインストールされている必要がある。
jna、slf4j-api(と適当なロガー実装モジュール)もクラスパスに含める必要がある。

動作確認に使っているバージョンは以下。

* libpcap 1.1.1
* WinPcap 4.1.2
* jna 5.1.0
* slf4j-api 1.7.25
* logback-core 1.0.0
* logback-classic 1.0.0

##### プラットフォーム #####
x86かx64プロセッサ上の以下のOSで動作することを確認した。

* Windows: XP, Vista, 7, [10](http://tbd.kaitoy.xyz/2016/01/12/pcap4j-with-four-native-libraries-on-windows10/), 2003 R2, 2008, 2008 R2, and 2012
* Linux
    * RHEL: 5, 6, and 7
    * CentOS: 5, 6, and 7
    * Ubuntu: 13
* UNIX
    * Solaris: 10
    * FreeBSD: 10

また、tomuteさんからMac OS Xで動いたとの[報告](http://tomute.hateblo.jp/entry/2013/01/27/003209)が。ありがとうございます。

他のアーキテクチャ/OSでも、JNAとlibpcapがサポートしていれば動く、と願う(FreeBSDはだめそう)。

##### その他 #####
Pcap4Jは管理者権限で実行する必要がある。
ただし、Linuxの場合、javaコマンドにケーパビリティ`CAP_NET_RAW`と`CAP_NET_ADMIN`を与えれば、非rootユーザでも実行できる。
ケーパビリティを付与するには次のコマンドを実行する: `setcap cap_net_raw,cap_net_admin=eip /path/to/java`

#### ドキュメント ####
最新のJavaDocは[こちら](https://www.javadoc.io/doc/org.pcap4j/pcap4j-distribution/1.8.1)。
各バージョンのJavaDocは[Maven Central Repository](http://search.maven.org/#search|ga|1|g%3A%22org.pcap4j%22)からダウンロードできる。

Pcap4Jのモジュール構成については[こちら](https://github.com/kaitoy/pcap4j/blob/v1/www/pcap4j_modules.md)。

Pcap4Jはpcapネイティブライブラリのラッパーなので、以下のドキュメントを読むとPcap4Jの使い方がわかる。

* [Programming with pcap](http://www.tcpdump.org/pcap.html)
* [WinPcap Manuals](http://www.winpcap.org/docs/default.htm)
* [pcap API と Pcap4J API の対応](https://github.com/kaitoy/pcap4j/blob/v1/www/api_mappings.md)

Pcap4Jプログラムの書き方は[サンプル](https://github.com/kaitoy/pcap4j/tree/v1/pcap4j-sample/src/main/java/org/pcap4j/sample)を見ると理解しやすい。

さらにPcap4Jを理解するには以下のドキュメントを参照。

* [Learn about packet class](https://github.com/kaitoy/pcap4j/blob/v1/www/Packet.md)
* [Learn about Packet Factory](https://github.com/kaitoy/pcap4j/blob/v1/www/PacketFactory.md)
* [サポートプロトコル追加方法](https://github.com/kaitoy/pcap4j/blob/v1/www/HowToAddProtocolSupport.md)
* [kaitoy's blog](http://tbd.kaitoy.xyz/tags/pcap4j/)

#### サンプル実行方法 ####
以下の例を参照。

* [org.pcap4j.sample.Loop](https://github.com/kaitoy/pcap4j/blob/v1/www/sample_Loop_ja.md)
* [org.pcap4j.sample.SendArpRequest](https://github.com/kaitoy/pcap4j/blob/v1/www/sample_SendArpRequest_ja.md)

Eclipse上でpcap4j-sampleにあるサンプルを実行する場合、
その実行構成のクラスパスタブのユーザー・エントリーの最初に、
pcap4j-packetfactory-staticプロジェクトかpcap4j-packetfactory-propertiesbasedプロジェクトを追加する必要がある。

#### Mavenプロジェクトでの使用方法 ####
pom.xmlに以下のような記述を追加する。

```xml
<project xmlns="http://maven.apache.org/POM/4.0.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
                      http://maven.apache.org/xsd/maven-4.0.0.xsd">
  ...
  <dependencies>
    <dependency>
      <groupId>org.pcap4j</groupId>
      <artifactId>pcap4j-core</artifactId>
      <version>1.8.1</version>
    </dependency>
    <dependency>
      <groupId>org.pcap4j</groupId>
      <artifactId>pcap4j-packetfactory-static</artifactId>
      <version>1.8.1</version>
    </dependency>
       ...
  </dependencies>
  ...
</project>
```

#### ネイティブライブラリのロードについて ####
デフォルトでは下記の条件でネイティブライブラリを検索し、ロードする。

* Windows
    * サーチパス: 環境変数`PATH`に含まれるパス等。([MSDN](https://msdn.microsoft.com/ja-jp/library/7d83bc18.aspx)参照。)
    * ファイル名: wpcap.dllとPacket.dll
* Linux/UNIX
    * サーチパス: OSに設定された共有ライブラリのサーチパス。例えば環境変数`LD_LIBRARY_PATH`に含まれるパス。
    * ファイル名: libpcap.so
* Mac OS X
    * サーチパス: OSに設定された共有ライブラリのサーチパス。例えば環境変数`DYLD_LIBRARY_PATH`に含まれるパス。
    * ファイル名: libpcap.dylib

カスタマイズのために、以下のJavaのシステムプロパティが使える。

* jna.library.path: サーチパスを指定する。
* org.pcap4j.core.pcapLibName: pcapライブラリ(wpcap.dllかlibpcap.soかlibpcap.dylib)へのフルパスを指定する。
* (Windowsのみ) org.pcap4j.core.packetLibName: packetライブラリ(Packet.dll)へのフルパスを指定する。

##### WinPcapかNpcapか #####
Windowsのネイティブpcapライブラリの選択肢にはWinPcapとNpcapがある。

WinPcapは2013/3/8に4.1.3(libpcap 1.0.0ベース)をリリースして以来開発が止まっているのに対して、
Npcapは現在も開発が続いているので、より新しい機能を使いたい場合などにはNpcapを選ぶといい。

WinPcapは`%SystemRoot%\System32\`にインストールされるので、何も気にしなくてもPcap4Jにロードされる。

一方Npcapはデフォルトで`%SystemRoot%\System32\Npcap\`にインストールされるので、
Pcap4Jがロードするためには以下のいずれかが必要となる。

* `PATH`に`%SystemRoot%\System32\Npcap\`を追加する。
* `jna.library.path`に`%SystemRoot%\System32\Npcap\`を指定する。
* `org.pcap4j.core.pcapLibName`に`%SystemRoot%\System32\Npcap\wpcap.dll`を指定して、
  `org.pcap4j.core.packetLibName`に`%SystemRoot%\System32\Npcap\Packet.dll`を指定する。
* Npcapを`WinPcap Compatible Mode`をオンにしてインストールする。

### Docker ###

[![](https://images.microbadger.com/badges/image/kaitoy/pcap4j.svg)](https://microbadger.com/images/kaitoy/pcap4j)

CentOSのPcap4J実行環境を構築したDockerイメージが[Docker Hub](https://registry.hub.docker.com/u/kaitoy/pcap4j/)にある。

`docker pull kaitoy/pcap4j`でダウンロードし、`docker run kaitoy/pcap4j:latest`でコンテナのeth0のパケットキャプチャーを実行できる。

このイメージはGitレポジトリにコミットがあるたびにビルドされる。

ビルド
------

1. WinPcap/Npcap/libpcapインストール:

    WindowsであればWinPcap、Linux/Unixであればlibpcapをインストールする。
    ビルド時に実行されるunit testで必要なので。

2. JDK インストール:

    JDKの9か10か11をダウンロードしてインストール。JAVA_HOMEを設定する。

3. そのJDKを[Maven toolchains](https://maven.apache.org/guides/mini/guide-using-toolchains.html)に追加:

    インストールしたJDKを[toolchains.xml](https://maven.apache.org/ref/3.6.1/maven-core/toolchains.html)に書いて`~/.m2/`に置く.
    `toolchains.xml`は以下のような感じになるはず。

    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <toolchains xmlns="http://maven.apache.org/TOOLCHAINS/1.1.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xsi:schemaLocation="http://maven.apache.org/TOOLCHAINS/1.1.0 http://maven.apache.org/xsd/toolchains-1.1.0.xsd">
      <toolchain>
        <type>jdk</type>
        <provides>
          <version>11</version>
        </provides>
        <configuration>
          <jdkHome>/path/to/jdk-11</jdkHome>
        </configuration>
      </toolchain>
    </toolchains>
    ```

4. Gitをインストール:

    [Git](http://git-scm.com/downloads)をダウンロードしてインストールする。
    Gitのインストールはビルドに必須ではないので、このステップはスキップしてもよい。

5. Pcap4Jのレポジトリのダウンロード:

    Gitをインストールした場合は`git clone git@github.com:kaitoy/pcap4j.git` を実行する。
    インストールしていない場合は、[zip](https://github.com/kaitoy/pcap4j/zipball/v1)でダウンロードして展開する。

6. ビルド:

    プロジェクトのルートディレクトリに`cd`して、`./mvnw install` を実行する。
    unit testを通すためにはAdministrator/root権限が必要。

コードに貢献
------------

1. このリポジトリをフォークする。
2. v1ブランチからブランチを作る。
3. コードを書く。

    * プロトコルサポートを追加するときは[このPR](https://github.com/kaitoy/pcap4j/pull/70)を参照。
    * このプロジェクトは[Google Java Style Guide](https://google.github.io/styleguide/javaguide.html)に従う。「`mvnw com.coveo:fmt-maven-plugin:format`」を実行するとフォーマットできる。

4. そのブランチからPRを送る。

ライセンス
----------

[LICENSE](/LICENSE)

コンタクト
----------

Kaito Yamada (kaitoy@pcap4j.org)
