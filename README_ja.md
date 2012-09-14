Pcap4J
======

Javaのパケットキャプチャライブラリ。パケットの作成・送信もできる。
ネイティブのパケットキャプチャライブラリである[libpcap](http://www.tcpdump.org/)
または[WinPcap](http://www.winpcap.org/)を[JNA](https://github.com/twall/jna)を
使ってラッピングして、JavaらしいAPIに仕上げたもの。

ダウンロード
------------

Pcap4J 0.9.11

* [pcap4j.jar](/downloads/Kaitoy/pcap4j/pcap4j.jar)

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
* Ethernet、IEEE802.1Q、ARP、IPv4(RFC791、RFC1349)、IPv6(RFC2460)、ICMPv4(RFC792)、UDPに対応。
* 各パケットクラスはシリアライズに対応。スレッドセーフ(実質的に不変)。
* ライブラリをいじらずに、対応プロトコルをユーザが追加できる。
* pcap APIのダンプファイル(Wiresharkのcapture fileなど)の読み込み、書き込み。


使い方
------

ドキュメントは作成中。
テストクラスやlibpcapのドキュメントを見ればなんとか使えるかも。
まだAPIは固まってなく、こっそりと変更する可能性がある。
J2SE 5.0以降で動く。
UNIX系ならlibpcap (多分)0.9.3以降、WindowsならWinPcap (多分)3.0以降がインストールされている必要がある。
jna、slf4j-api(と適当なロガー実装モジュール)もクラスパスに含める必要がある。

動作確認に使っているバージョンは以下。

* libpcap 1.1.1
* WinPcap 4.1.2
* jna 3.3.0
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

ビルド
------
開発に使っている環境は以下。

* [Eclipse](http://www.eclipse.org/) Java EE IDE for Web Developers Indigo Service Release 1([Pleiades](http://mergedoc.sourceforge.jp/) All in One 3.7.1.v20110924)
* [M2E - Maven Integration for Eclipse](http://eclipse.org/m2e/download/) 1.0.100.20110804-1717

ビルド手順は以下。

1. Eclipseインストール
   ダウンロードして解凍するだけ。
2. m2eインストール
   EclipseのGUIで、[ヘルプ]＞[新規ソフトウェアのインストール] を開き、
   「作業対象」に http://download.eclipse.org/technology/m2e/releases を入力してEnter。
   m2e - Eclipse用のMaven統合をチェックして「次へ」。
   使用条件の条項に同意しますにチェックして「完了」。
   m2eのインストールが完了したらEclipseを再起動。
3. Gitをインストール
4. Pcap4Jのレポジトリのダウンロード
   `git clone git@github.com:kaitoy/pcap4j.git` を実行する。
5. プロジェクトのインポート
  EclipseのGUIで、[ファイル]＞[インポート] を開き、
  「一般」の「既存プロジェクトをワークスペースへ」で 3. でダウンロードしたレポジトリ内のプロジェクトをインポートする。
6. ビルド
   EclipseのGUIのプロジェクト・エクスプローラーで、Pcap4Jのプロジェクトを右クリックして、
   [実行]＞[Maven package] か [実行]＞[Maven install] を実行する。

因みに、m2eは旧[m2eclipse](http://m2eclipse.sonatype.org/)。
m2eclipseでビルドしたい場合は、2. をスキップして、4. でMavenプロジェクトの方をインポートすればよい。

ライセンス
----------

Pcap4J is distributed under the MIT license.

    Copyright (c) 2011-2012 Kaito Yamada
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

Pcap4J 0.9.11 を使ったSNMPネットワークシミュレータ、SNeO。
とりあえず置いておくだけ。
今のところ商用でもなんでも無料で使用可。コピーも再配布も可。

SNeO 1.0.10

* [sneo.jar](/downloads/Kaitoy/pcap4j/sneo.jar)
