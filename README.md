i4 Wake-On-LAN Provider
=======================

Der Lehrstuhl bewegt sich in Richtung [Green IT](https://de.wikipedia.org/wiki/Green_IT) und möchte nun eine Infrastruktur verwenden, bei der Rechner während Nichtbenutzung abgeschalten und nur bei Bedarf mittels *Wake-On-LAN* wieder gestartet werden können.

Eine kleine Client-Server-Implementierung um ein [Magic Packet](https://de.wikipedia.org/wiki/Wake_On_LAN#Magic_Packet) an einen Zielhost im Lehrstuhlnetz zu senden.

Der Hostname wird dabei via DHCP Konfiguration aufgelöst:
Der Python3 Server auf `i4woke` sendet die Nachricht als Broadcast mit der Ziel-MAC an das entsprechende VLAN -- sofern es Zugriff darauf hat (derzeit 308, 688 & 689 sowie 42).

Es muss vom Client schlicht der Hostname an den Server (Port `8423`) geschickt werden, ein `success` signalisiert die erfolgreiche Versendung des Packets (`failed` entsprechend einen Fehler, z.B. bei der Auflösung des Hostnames).
Das ganze ist in [ein Bash-Skript gepackt](client/woke.sh) und liegt auf einigen Systemen auch bereits im `PATH`.
```
$  wake faui49man{1,2,42}
i4 Wake-On-LAN Client
 - faui49man1           [success]
 - faui49man2           [success]
 - faui49man42          [failed]
```

Servereinrichtung
-----------------

Notwendige Python Pakete installieren und dieses Repo auschecken, z.B. unter `/opt/wake-on-lan`:

	apt install python3 python3-pyparsing python3-psutil
	git clone git@gitlab.cs.fau.de:i4/infra/wake-on-lan.git /opt/wake-on-lan

Ein Systembenutzer ist hilfreich:

	sudo adduser --system --no-create-home --disabled-password --disabled-login wakeonlan

Ggf [systemd-Service](wake-on-lan-provider.service) einrichten

	cp wake-on-lan-provider.service /etc/systemd/system/
	systemctl daemon-reload
	systemctl enable wake-on-lan-provider.service
	systemctl start wake-on-lan-provider.service

Standardmäßig werden DHCP Konfigurationsdateien im Ordner `/etc/wake-on-lan/` geladen, entsprechend kann einfach (automatisch) die `/var/lib/cfengine2/distributed/dhcp_server/etc/dhcp/clients.conf` bei Änderungen dort hin kopiert werden.


Konfiguration auf Zielrechner
-----------------------------

Damit Rechner aufgeweckt werden können, muss Wake-On-LAN im BIOS und auf dem Netzwerkadapter aktiviert werden.
Letzteres kann z,B, bei einem Interface `eth0` entweder manuell durch

	sudo ethtool -s eth0 wol g

oder mittels einer *udev*-Regel `/etc/udev/rules.d/99-wol.rules` mit dem Inhalt

	ACTION=="add", SUBSYSTEM=="net", KERNEL=="eth*", RUN+="/usr/sbin/ethtool -s $name wol g"

geschehen, alternativ ist auch ein *systemd*-Service möglich.

Außerdem soll der Rechner auch bei Inaktivität schlafen gelegt werden, hierzu eignet sich das Werkzeug [autosuspend](https://github.com/languitar/autosuspend/).
Eine Beispielkonfiguration für den Lehrstuhl befindet sich im gleichnamigen Ordner.


Weitere Informationen
---------------------

Ein Überblick zu diesem Thema ist auf dem [Lehrstuhl-Blog](https://sys.cs.fau.de/2022/10/24/green-it) zu finden.
Die hier vorliegenden Skripte und Konfigurationen sind auf das Lehrstuhlnetz zugeschnitten, sollen jedoch auch demonstrieren, wie einfach eine Energieeinsparung umgesetzt werden kann.

Es sollte mit geringem Aufwand möglich sein, diesen Ansatz auf eigene Netze zu adaptieren, die in diesem Repo zur Verfügung gestellten Dateien dürfen dazu gerne verwendet und angepasst werden.
