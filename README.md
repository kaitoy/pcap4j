Pcap4J
======

Javaのパケットキャプチャライブラリ。パケットの作成・送信もできる。<br>
ネイティブのパケットキャプチャライブラリである[libpcap](http://www.tcpdump.org/)または[WinPcap](http://www.winpcap.org/)を、<br>
[JNA](https://github.com/twall/jna)を使ってラッピングして、JavaらしいAPIに仕上げたもの。<br>

ダウンロード
------------

Pcap4J 0.9.9

* [pcap4j.jar](/downloads/Kaitoy/pcap4j/pcap4j.jar)

開発経緯
--------

SNMPネットワークシミュレータをJavaで作っていて、パケットキャプチャをしたくなったが、<br>
Raw Socketを使って自力でやるのは大変そうなので pcap APIを使うことに。<br>

pcap APIの実装は、UNIX系にはlibpcap、WindowsにはWinPcapがあるが、いずれもネイティブライブラリ。<br>
これらのJavaラッパは[jpcap](http://jpcap.sourceforge.net/)や[jNetPcap](http://jnetpcap.com/)が既にあるが、<br>
これらはパケットキャプチャに特化していて、パケット作成・送信がしにくいような気がした。<br>

[Jpcap](http://netresearch.ics.uci.edu/kfujii/Jpcap/doc/)はパケット作成・送信もやりやすいけど、<br>
ICMPのキャプチャ周りにバグがあって使えなかった。結構前から開発が止まっているようだし。<br>
ということで自作した。<br>

機能
----

* ネットワークインターフェースからパケットをキャプチャし、Javaのオブジェクトに変換する。
* パケットオブジェクトにアクセスしてパケットのフィールドを取得、編集できる。
* 手動でパケットオブジェクトを組み立てることもできる。
* パケットオブジェクトは、現実のネットワークに送信できる。
* pcap APIのダンプファイル(Wiresharkのcapture fileなど)の読み込み、書き込み。
* Ethernet、IEEE802.1Q、ARP、IPv4(オプションなし)、ICMPv4、UDPに対応。
* 各パケットクラスはシリアライズに対応。スレッドセーフ(実質的に不変)。
* ライブラリをいじらずに、対応プロトコルをユーザが追加できる。


使い方
------

ドキュメントは作成中。<br>
テストクラスやlibpcapのドキュメントを見ればなんとか使えるかも。<br>
まだAPIは固まってなく、こっそりと変更する可能性がある。<br>
JRE1.5以降で動く。<br>
UNIX系ならlibpcap (多分)0.9.3以降、WindowsならWinPcap (多分)3.0以降がインストールされている必要がある。<br>
jna、slf4j-api(と適当なロガー実装モジュール)もクラスパスに含める必要がある。<br>

動作確認に使っているバージョンは以下。

* libpcap 1.1.1
* WinPcap 4.1.2
* jna 3.3.0
* slf4j-api 1.6.4
* logback-core 1.0.1
* logback-classic 1.0.1


ビルド
------
開発に使っている環境は以下。

* [Eclipse](http://www.eclipse.org/) Java EE IDE for Web Developers Indigo Service Release 1([Pleiades](http://mergedoc.sourceforge.jp/) All in One 3.7.1.v20110924)
* [M2E - Maven Integration for Eclipse](http://eclipse.org/m2e/download/) 1.0.100.20110804-1717

ビルド手順は以下。

1. Eclipseインストール<br>
   ダウンロードして解凍するだけ。
2. M2Eインストール<br>
   EclipseのGUIで、[ヘルプ]＞[新規ソフトウェアのインストール] を開き、<br>
   「作業対象」に http://download.eclipse.org/technology/m2e/releases を入力してEnter。<br>
   m2e - Eclipse用のMaven統合をチェックして「次へ」。<br>
   使用条件の条項に同意しますにチェックして「完了」。<br>
   M2Eのインストール完了したらEclipseを再起動。<br>
3. Pcap4Jのレポジトリのダウンロード<br>
   `git clone git@github.com:kaitoy/pcap4j.git` を実行する。
4. プロジェクトのインポート<br>
  EclipseのGUIで、[ファイル]＞[インポート] を開き、<br>
  「一般」の「既存プロジェクトをワークスペースへ」で 3. でダウンロードしたレポジトリ内のプロジェクトをインポートする。
5. ビルド<br>
   EclipseのGUIのプロジェクト・エクスプローラーで、Pcap4Jのプロジェクトを右クリックして、<br>
   [実行]＞[Maven package] か [実行]＞[Maven install] を実行する。

因みに、M2Eは旧[m2eclipse](http://m2eclipse.sonatype.org/)。<br>
m2eclipseでビルドしたい場合は、2. をスキップして、4. でMavenプロジェクトの方をインポートすればよい。<br>

ライセンス
----------

Pcap4J is provided distributed under the MIT license.<br>

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

Pcap4J 0.9.9 を使ったSNMPネットワークシミュレータ、SNeO。<br>
とりあえず置いておくだけ。<br>
今のところ商用でもなんでも無料で使用可。コピーも再配布も可。<br>

SNeO 1.0.8

* [sneo.jar](/downloads/Kaitoy/pcap4j/sneo.jar)
