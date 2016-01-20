[English](https://github.com/kaitoy/pcap4j)

<img alt="Pcap4J" title="Pcap4J" src="https://github.com/kaitoy/pcap4j/raw/master/www/images/logos/pcap4j-logo-color.png" width="70%" style="margin: 0px auto; display: block;" />

[ロゴ](/www/logos.md)

[![Slack](http://pcap4j-slackin.herokuapp.com/badge.svg)](https://pcap4j-slackin.herokuapp.com/)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/org.pcap4j/pcap4j-distribution/badge.svg)](https://maven-badges.herokuapp.com/maven-central/org.pcap4j/pcap4j-distribution)

[![Build Status](https://travis-ci.org/kaitoy/pcap4j.svg)](https://travis-ci.org/kaitoy/pcap4j)
[![Build status](https://ci.appveyor.com/api/projects/status/github/kaitoy/pcap4j?branch=master&svg=true)](https://ci.appveyor.com/project/kaitoy/pcap4j/branch/master)
[![Coverage Status](https://coveralls.io/repos/kaitoy/pcap4j/badge.svg)](https://coveralls.io/r/kaitoy/pcap4j)

Pcap4J
======

パケットをキャプチャ・作成・送信するためのJavaライブラリ。
ネイティブのパケットキャプチャライブラリである[libpcap](http://www.tcpdump.org/)
または[WinPcap](http://www.winpcap.org/)を[JNA](https://github.com/twall/jna)を
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
    * [Docker](#docker)
* [ビルド](#ビルド)
    * [Mavenコマンドでのビルド手順 (推奨)](#mavenコマンドでのビルド手順-推奨)
    * [Eclipse上でのビルド手順](#eclipse上でのビルド手順)
* [ライセンス](#ライセンス)
* [コンタクト](#コンタクト)
* [おまけ](#おまけ)

ダウンロード
------------

Maven Central Repositoryからダウンロードできる。

* Pcap4J 1.6.2
    * ソースなし: [pcap4j-distribution-1.6.2-bin.zip](http://search.maven.org/remotecontent?filepath=org/pcap4j/pcap4j-distribution/1.6.2/pcap4j-distribution-1.6.2-bin.zip)
    * ソース入り: [pcap4j-distribution-1.6.2-src.zip](http://search.maven.org/remotecontent?filepath=org/pcap4j/pcap4j-distribution/1.6.2/pcap4j-distribution-1.6.2-src.zip)
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
    * Ethernet、Linux SLL、raw IP、PPP (RFC1661、RFC1662)、BSD (Mac OS X) loopback encapsulation
    * IEEE802.1Q
    * ARP
    * IPv4 (RFC791、RFC1349)、IPv6 (RFC2460)
    * ICMPv4 (RFC792)、ICMPv6 (RFC4443, RFC4861)
    * TCP (RFC793、RFC2018、draft-ietf-tcpm-1323bis-21)、UDP
* 各ビルトインパケットクラスはシリアライズに対応。スレッドセーフ(実質的に不変)。
* ライブラリをいじらずに、対応プロトコルをユーザが追加できる。
* pcapのダンプファイル(Wiresharkのcapture fileなど)の読み込み、書き込み。

使い方
------

#### システム要件 ####

##### ライブラリ等の依存 #####
1.1.0以前のはJ2SE 5.0以降で動く。1.2.0以降のはJ2SE 6.0以降で動く。
UNIX系ならlibpcap 1.0.0以降、WindowsならWinPcap (多分)3.0以降がインストールされている必要がある。
jna、slf4j-api(と適当なロガー実装モジュール)もクラスパスに含める必要がある。

動作確認に使っているバージョンは以下。

* libpcap 1.1.1
* WinPcap 4.1.2
* jna 4.1.0
* slf4j-api 1.7.12
* logback-core 1.0.0
* logback-classic 1.0.0

##### プラットフォーム #####
x86かx64プロセッサ上の以下のOSで動作することを確認した。

* Windows: XP, Vista, 7, [10](http://tbd.kaitoy.xyz/2016/01/12/pcap4j-with-four-native-libraries-on-windows10/), 2003 R2, 2008, 2008 R2, and 2012
* Linux
    * RHEL: 5 and 6
    * CentOS: 5
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
最新のJavaDocは[こちら](http://kaitoy.github.com/pcap4j/javadoc/latest/en)。
各バージョンのJavaDocは[Maven Central Repository](http://search.maven.org/#search|ga|1|g%3A%22org.pcap4j%22)からダウンロードできる。

Pcap4Jのモジュール構成については[こちら](/www/pcap4j_modules.md)。

Pcap4Jはlibpcap/WinPcapのラッパーなので、以下のドキュメントを読むとPcap4Jの使い方がわかる。

* [Programming with pcap](http://www.tcpdump.org/pcap.html)
* [WinPcap Manuals](http://www.winpcap.org/docs/default.htm)
* [pcap API と Pcap4J API の対応](/www/api_mappings.md)

Pcap4Jプログラムの書き方は[サンプル](https://github.com/kaitoy/pcap4j/tree/master/pcap4j-sample/src/main/java/org/pcap4j/sample)を見ると理解しやすい。

さらにPcap4Jを理解するには以下のドキュメントを参照。

* [Learn about packet class](/www/Packet.md)
* [Learn about Packet Factory](/www/PacketFactory.md)
* [サポートプロトコル追加方法](/www/HowToAddProtocolSupport.md)
* [kaitoy's blog](http://tbd.kaitoy.xyz/tags/pcap4j/)

#### サンプル実行方法 ####
以下の例を参照。

* [org.pcap4j.sample.Loop](/www/sample_Loop_ja.md)
* [org.pcap4j.sample.SendArpRequest](/www/sample_SendArpRequest_ja.md)

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
      <version>1.6.2</version>
    </dependency>
    <dependency>
      <groupId>org.pcap4j</groupId>
      <artifactId>pcap4j-packetfactory-static</artifactId>
      <version>1.6.2</version>
    </dependency>
       ...
  </dependencies>
  ...
</project>
```

#### ネイティブライブラリのロードについて ####
デフォルトでは下記の条件でネイティブライブラリを検索し、ロードする。

* Windows
    * サーチパス: 環境変数`PATH`に含まれるパス。
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

### Docker ###
CentOSのPcap4J実行環境を構築したDockerイメージが[Docker Hub](https://registry.hub.docker.com/u/kaitoy/pcap4j/)にある。

`docker pull kaitoy/pcap4j`でダウンロードし、`docker run kaitoy/pcap4j:latest`でコンテナのeth0のパケットキャプチャーを実行できる。

このイメージはGitレポジトリにコミットがあるたびにビルドされる。

ビルド
------
開発に使っている環境は以下。

* [Eclipse](http://www.eclipse.org/) Java EE IDE for Web Developers Indigo Service Release 1([Pleiades](http://mergedoc.sourceforge.jp/) All in One 3.7.1.v20110924)
* [M2E - Maven Integration for Eclipse](http://eclipse.org/m2e/download/) 1.0.100.20110804-1717
* [Apache Maven](http://maven.apache.org/) 3.0.5

#### Mavenコマンドでのビルド手順 (推奨) ####
1. WinPcap/libpcapインストール:<br>
   WindowsであればWinPcap、Linux/Unixであればlibpcapをインストールする。
   ビルド時に実行されるunit testで必要なので。
2. JDK 1.6+インストール:<br>
   JDKの1.6以上をダウンロードしてインストール。JAVA_HOMEを設定する。
3. Mavenインストール:<br>
   Mavenの3.0.5以上をインストールして、そのbinディレクトリにPATHを通す。
4. Gitをインストール:<br>
   [Git](http://git-scm.com/downloads)をダウンロードしてインストールする。
   Gitのインストールはビルドに必須ではないので、このステップはスキップしてもよい。
5. Pcap4Jのレポジトリのダウンロード:<br>
   Gitをインストールした場合は`git clone git@github.com:kaitoy/pcap4j.git` を実行する。
   インストールしていない場合は、[zip](https://github.com/kaitoy/pcap4j/zipball/master)でダウンロードして展開する。
6. ビルド:<br>
   プロジェクトのルートディレクトリに`cd`して、`mvn install` を実行する。
   unit testを通すためにはAdministrator/root権限が必要。

#### Eclipse上でのビルド手順 ####
1. WinPcap/libpcapインストール:<br>
   WindowsであればWinPcap、Linux/Unixであればlibpcapをインストールする。
   ビルド時に実行されるunit testで必要なので。
2. Eclipseインストール:<br>
   [Eclipse.org](http://www.eclipse.org/downloads/)あたりでダウンロードして解凍するだけ。
3. M2Eインストール:<br>
   EclipseのGUIで、[ヘルプ]＞[新規ソフトウェアのインストール] を開き、
   ***作業対象***に http://download.eclipse.org/technology/m2e/releases を入力してEnter。
   ***m2e - Eclipse用のMaven統合***をチェックして***次へ***。
   ***使用条件の条項に同意します***にチェックして***完了***。
   m2eのインストールが完了したらEclipseを再起動。
4. Gitをインストール:<br>
   [Git](http://git-scm.com/downloads)をダウンロードしてインストールする。
   Gitのインストールはビルドに必須ではないので、このステップはスキップしてもよい。
5. Pcap4Jのレポジトリのダウンロード:<br>
   Gitをインストールした場合は`git clone git@github.com:kaitoy/pcap4j.git` を実行する。
   インストールしていない場合は、[zip](https://github.com/kaitoy/pcap4j/zipball/master)でダウンロードして展開する。
6. プロジェクトのインポート:<br>
   EclipseのGUIで、***ファイル ＞ インポート*** を開き、
   ***一般 ＞ 既存プロジェクトをワークスペースへ***でPcap4Jの全プロジェクトをインポートする。
7. ビルド:<br>
   EclipseのGUIの***プロジェクト・エクスプローラー***で、Pcap4Jの親プロジェクトを右クリックして、
   ***実行 ＞ Maven install***を実行する。
   unit testを通すためにはAdministrator/root権限が必要。

因みに、M2Eは旧[m2eclipse](http://m2eclipse.sonatype.org/)。
m2eclipseでビルドしたい場合は、ステップ2をスキップして、ステップ4でMavenプロジェクトの方をインポートすればよい。

ライセンス
----------

Pcap4J is distributed under the MIT license.

    Copyright (c) 2011-2015 Pcap4J.org

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

コンタクト
----------

Kaito Yamada (kaitoy@pcap4j.org)

おまけ
------

Pcap4J を使ったSNMPネットワークシミュレータ、SNeO。Githubに公開しました: https://github.com/kaitoy/sneo
