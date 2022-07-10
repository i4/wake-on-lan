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

