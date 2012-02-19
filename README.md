Pcap4J
======

Javaのパケットキャプチャライブラリ。パケットの作成・送信もできる。<br>
ネイティブのパケットキャプチャライブラリである[libpcap](http://www.tcpdump.org/)または[WinPcap](http://www.winpcap.org/)を、<br>
[JNA](https://github.com/twall/jna)を使ってラッピングして、JavaらしいAPIに仕上げたもの。<br>

ダウンロード
------------

pcap4j 0.9.5

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

* パケットのキャプチャ、解析、作成、送信。
* Ethernet、IEEE802.1Q、ARP、IPv4(オプションなし)、ICMPv4、UDPに対応。
* ライブラリをいじらずに、対応プロトコルをユーザが追加できる。


使い方
------

ドキュメントは作成中。<br>
テストクラスやlibpcapのドキュメントを見ればなんとか使えるかも。<br>
UNIX系ならlibpcap、WindowsならWinPcapがインストールされている必要がある。<br>
jna、log4jもクラスパスに含める必要がある。<br>

動作確認済みのバージョンは以下。

* libpcap 1.1.1
* WinPcap 4.1.2
* jna 3.3.0
* log4j 1.2.14


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
3. pcap4jのレポジトリのダウンロード<br>
   `git clone git@github.com:kaitoy/pcap4j.git` を実行する。
4. プロジェクトのインポート<br>
  EclipseのGUIで、[ファイル]＞[インポート] を開き、<br>
  「一般」の「既存プロジェクトをワークスペースへ」で 3. でダウンロードしたレポジトリ内のプロジェクトをインポートする。
5. ビルド<br>
   EclipseのGUIのプロジェクト・エクスプローラーで、pcap4jのプロジェクトを右クリックして、<br>
   [実行]＞[Maven package] か [実行]＞[Maven install] を実行する。

因みに、M2Eは旧[m2eclipse](http://m2eclipse.sonatype.org/)。<br>
m2eclipseでビルドしたい場合は、2. をスキップして、4. でMavenプロジェクトの方をインポートすればよい。<br>

ライセンス
----------

pcap4j is provided under the LGPL, version 2.1 or later.<br>

おまけ
------

pcap4j 0.9.5 を使ったSNMPネットワークシミュレータ、SNeO。<br>
とりあえず置いておくだけ。<br>
商用でもなんでも無料で使用可。コピーも再配布も可。<br>

SNeO 1.0.4

* [sneo.jar](/downloads/Kaitoy/pcap4j/sneo.jar)
