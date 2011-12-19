Pcap4J
======

Javaのパケットキャプチャライブラリ。パケットの作成・送信もできる。

ネイティブのパケットキャプチャライブラリであるlibpcap( http://www.tcpdump.org/ )またはWinPcap( http://www.winpcap.org/ )を、

JNA( https://github.com/twall/jna )を使ってラッピングして、JavaらしいAPIに仕上げた(つもりの)もの。

ダウンロード
============

pcap4j1.0.0

* [pcap4j.jar](/downloads/Kaitoy/pcap4j/pcap4j.jar)

開発経緯
========

SNMPネットワークシミュレータをJavaで作っていて、パケットキャプチャをしたくなったが、

Raw Socketを使って自力でやるのは大変そうなので、pcap APIを使うことに。


pcap APIの実装は、UNIX系にはlibpcap、WindowsにはWinPcapがあるが、いずれもネイティブライブラリ。

これらのJavaラッパはjpcap( http://jpcap.sourceforge.net/ )やjNetPcap( http://jnetpcap.com/ )が既にあるが、

これらはパケットキャプチャに特化していて、パケット作成・送信がしにくいような気がした。

Jpcap( http://netresearch.ics.uci.edu/kfujii/Jpcap/doc/ )はパケット作成・送信もやりやすいけど、

ICMPのキャプチャ周りにバグがあって使えなかった。結構前から開発が止まっているようだし。

ということで自作した。

機能
====

* パケットのキャプチャ、作成、送信。
* Ethernet、ARP、IPv4、ICMPv4、UDPに対応。
* ライブラリをいじらずに、対応プロトコルをユーザが追加できる。
  
使い方
======

ドキュメントは作成中。

テストクラスやlibpcapのドキュメントを見れば…


UNIX系ならlibpcap、WindowsならWinPcapがインストールされている必要がある。

jnaもクラスパスに含める必要がある。

動作確認済みのバージョンは以下。

* libpcap1.1.1
* WinPcap4.1.2
* jna3.3.0
  
ライセンス
==========

pcap4j is provided under the LGPL, version 2.1 or later.

おまけ
======

pcap4jを使ったSNMPネットワークシミュレータ、SnmpNetSim。

とりあえず置いておくだけ。
商用でもなんでも無料で使用可。コピーも再配布も可。

SnmpNetSim0.9.0

* [snmpnetsim.jar](/downloads/Kaitoy/pcap4j/snmpnetsim.jar)
