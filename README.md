# server_setup
### Первичная настройка сервера

Выполняется как обычно. 
 ```
 apt update
 apt upgrade -y
 
 groupadd username
 useradd -m -g users -G username,audio,video,sudo -s /bin/bash username
 mkdir /home/username/.ssh
 touch /home/username/.ssh/authorized_keys
 
 vim /etc/ssh/sshd_config
 
 PasswordAuthentication no
 PubkeyAuthentication yes
 PermitRootLogin no
 
 systemctl restart sshd.service
 
 su username
 ```

Настраиваем перенаправление пакетов на уровне ядра:
```
fs.file-max = 51200

net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.netdev_max_backlog = 250000
net.core.somaxconn = 4096

net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_tw_recycle = 0
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.ip_local_port_range = 10000 65000
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 5000
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mem = 25600 51200 102400
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_congestion_control = hybla
net.ipv4.ip_forward = 1
net.ipv6.conf.default.forwarding = 1
net.ipv6.conf.all.forwarding = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.proxy_arp = 0
net.ipv4.conf.default.send_redirects = 1
net.ipv4.conf.all.send_redirects = 0
```

Настраиваем Iptables для предотвращения брутфорса
```
iptables -A INPUT -m state --state NEW,ESTABLISHED,RELATED --source x.x.x.x -p tcp --dport 22 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set --name SSH -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 22 -m recent --update --seconds 60 --hitcount 4 --rttl --name SSH -j LOG --log-prefix "SSH_brute_force "
sudo iptables -A INPUT -p tcp --dport 22 -m recent --update --seconds 60 --hitcount 4 --rttl --name SSH -j DROP
```
Настраиваем UFW:
```
sudo ufw allow 22/tcp
sudo ufw allow 443
sudo ufw allow 58712/udp
sudo ufw reload
```

### Установка и настройка shadowsocks + v2ray-plugin
#### На сервере
 ```
sudo apt update
sudo apt install shadowsocks-libev
```
Скачиваем и распаковываем последний релиз v2ray-plugin (проверить архитектуру!)
```
cd /etc/shadowsocks-libev
sudo wget https://github.com/shadowsocks/v2ray-plugin/releases/download/v1.3.1/v2ray-plugin-linux-{%%architecture%%}-v1.3.1.tar.gz
sudo tar xzvf v2ray-plugin-linux-{%%architecture%%}-v1.3.1.tar.gz
```
регистрируем доменное имя mydomain.me, указываем сервера имен с cloudflare
в аккаунте cloudflare прописываем @ - ip address
выпускаем tls-сертификаты
 ```
git clone https://github.com/acmesh-official/acme.sh.git
cd ./acme.sh
./acme.sh --install 

~/.acme.sh/acme.sh --issue --dns dns_cf -d mydomain.me
```
правим конфигаруционный файл shadowsocks:
```
sudo vim /etc/shadowsocks-libev/config.json

{
    "server":"0.0.0.0",
    "mode":"tcp_and_udp",
    "server_port":443,
    "password":"****",
    "timeout":60,
    "fast_open":true,
    "port_reuse":true,
    "plugin":"/etc/shadowsocks-libev/v2ray-plugin",
    "plugin_opts":"server;tls;host=mydomain.me;cert=/home/username/.acme.sh/mydomain.me/fullchain.cer;key=/home/username/.acme.sh/mydomain.me/mydomain.me.key;fast-open",
    "method":"aes-256-gcm",
    "nameserver":"1.1.1.1"
}
```
выполняем 
```
sudo ss-server -c /etc/shadowsocks-libev/config.json
```

#### на клиенте
##### разрешаем форвардинг пакетов
```
sudo echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sudo sysctl-p
```

Правим /etc/ufw/before.rules до таблицы *filter

 ```
 *nat
-A POSTROUTING -o eth0 -j MASQUERADE 
COMMIT
```
Правим дефолтную политику в отношении форвардинга пакетов:
```
sudo vim /etc/default/ufw

DEFAULT_FORWARD_POLICY="ACCEPT"
```

Конфигурационный файл клиента:
```
{
    "server":"server-ip",
    "mode":"tcp_and_udp",
    "server_port":443,
    "local_port":1080,
    "password":"****",
    "timeout":60,
    "method":"aes-256-gcm",
    "plugin":"/etc/shadowsocks-libev/v2ray-plugin",
    "plugin_opts":"tls;host=hostname.dn;fast-open",
    "fast_open":true,
    "nameserver":"1.1.1.1"
}
```

Скрипт для ss-redirect (используем для теста, в продакшене будет крутиться ss-tunnel)

```
#!/bin/bash

start_ssredir() {
    # please modify MyIP, MyPort, etc.
    (ss-redir -c /etc/shadowsocks-libev/config.json  --no-delay -u -T -v </dev/null &>>/var/log/ss-redir.log &)
}

stop_ssredir() {
    kill -9 $(pidof ss-redir) &>/dev/null
}

start_iptables() {
    ##################### SSREDIR #####################
    iptables -t mangle -N SSREDIR

    # connection-mark -> packet-mark
    iptables -t mangle -A SSREDIR -j CONNMARK --restore-mark
    iptables -t mangle -A SSREDIR -m mark --mark 0x2333 -j RETURN

    # please modify MyIP, MyPort, etc.
    # ignore traffic sent to ss-server
    iptables -t mangle -A SSREDIR -p tcp -d server-ip --dport 443 -j RETURN
    iptables -t mangle -A SSREDIR -p udp -d server-ip --dport 443 -j RETURN

    # ignore traffic sent to reserved addresses
    iptables -t mangle -A SSREDIR -d 0.0.0.0/8          -j RETURN
    iptables -t mangle -A SSREDIR -d 10.0.0.0/8         -j RETURN
    iptables -t mangle -A SSREDIR -d 100.64.0.0/10      -j RETURN
    iptables -t mangle -A SSREDIR -d 127.0.0.0/8        -j RETURN
    iptables -t mangle -A SSREDIR -d 169.254.0.0/16     -j RETURN
    iptables -t mangle -A SSREDIR -d 172.16.0.0/12      -j RETURN
    iptables -t mangle -A SSREDIR -d 192.0.0.0/24       -j RETURN
    iptables -t mangle -A SSREDIR -d 192.0.2.0/24       -j RETURN
    iptables -t mangle -A SSREDIR -d 192.88.99.0/24     -j RETURN
    iptables -t mangle -A SSREDIR -d 192.168.0.0/16     -j RETURN
    iptables -t mangle -A SSREDIR -d 198.18.0.0/15      -j RETURN
    iptables -t mangle -A SSREDIR -d 198.51.100.0/24    -j RETURN
    iptables -t mangle -A SSREDIR -d 203.0.113.0/24     -j RETURN
    iptables -t mangle -A SSREDIR -d 224.0.0.0/4        -j RETURN
    iptables -t mangle -A SSREDIR -d 240.0.0.0/4        -j RETURN
    iptables -t mangle -A SSREDIR -d 255.255.255.255/32 -j RETURN
    
    # mark the first packet of the connection
    iptables -t mangle -A SSREDIR -p tcp --syn                      -j MARK --set-mark 0x2333
    iptables -t mangle -A SSREDIR -p udp -m conntrack --ctstate NEW -j MARK --set-mark 0x2333

    # packet-mark -> connection-mark
    iptables -t mangle -A SSREDIR -j CONNMARK --save-mark

    ##################### OUTPUT #####################
    # proxy the outgoing traffic from this machine
    iptables -t mangle -A OUTPUT -p tcp -m addrtype --src-type LOCAL ! --dst-type LOCAL -j SSREDIR
    iptables -t mangle -A OUTPUT -p udp -m addrtype --src-type LOCAL ! --dst-type LOCAL -j SSREDIR

    ##################### PREROUTING #####################
    # proxy traffic passing through this machine (other->other)
    iptables -t mangle -A PREROUTING -p tcp -m addrtype ! --src-type LOCAL ! --dst-type LOCAL -j SSREDIR
    iptables -t mangle -A PREROUTING -p udp -m addrtype ! --src-type LOCAL ! --dst-type LOCAL -j SSREDIR
    # hand over the marked package to TPROXY for processing
    iptables -t mangle -A PREROUTING -p tcp -m mark --mark 0x2333 -j TPROXY --on-ip 127.0.0.1 --on-port 1080
    iptables -t mangle -A PREROUTING -p udp -m mark --mark 0x2333 -j TPROXY --on-ip 127.0.0.1 --on-port 1080
}

stop_iptables() {
    ##################### PREROUTING #####################
    iptables -t mangle -D PREROUTING -p tcp -m mark --mark 0x2333 -j TPROXY --on-ip 127.0.0.1 --on-port 1080 &>/dev/null
    iptables -t mangle -D PREROUTING -p udp -m mark --mark 0x2333 -j TPROXY --on-ip 127.0.0.1 --on-port 1080 &>/dev/null

    iptables -t mangle -D PREROUTING -p tcp -m addrtype ! --src-type LOCAL ! --dst-type LOCAL -j SSREDIR &>/dev/null
    iptables -t mangle -D PREROUTING -p udp -m addrtype ! --src-type LOCAL ! --dst-type LOCAL -j SSREDIR &>/dev/null

    ##################### OUTPUT #####################
    iptables -t mangle -D OUTPUT -p tcp -m addrtype --src-type LOCAL ! --dst-type LOCAL -j SSREDIR &>/dev/null
    iptables -t mangle -D OUTPUT -p udp -m addrtype --src-type LOCAL ! --dst-type LOCAL -j SSREDIR &>/dev/null
     ##################### SSREDIR #####################
    iptables -t mangle -F SSREDIR &>/dev/null
    iptables -t mangle -X SSREDIR &>/dev/null
}

start_iproute2() {
    ip route add local default dev lo table 100
    ip rule  add fwmark 0x2333        table 100
}

stop_iproute2() {
    ip rule  del   table 100 &>/dev/null
    ip route flush table 100 &>/dev/null
}

start_resolvconf() {
    # or nameserver 8.8.8.8, etc.
    echo "nameserver 1.1.1.1" >/etc/resolv.conf
}
stop_resolvconf() {
    echo "nameserver 114.114.114.114" >/etc/resolv.conf
}

start() {
    echo "start ..."
    start_ssredir
    start_iptables
    start_iproute2
    start_resolvconf
    echo "start end"
}

stop() {
    echo "stop ..."
    stop_resolvconf
    stop_iproute2
    stop_iptables
    stop_ssredir
    echo "stop end"
}
restart() {
    stop
    sleep 1
    start
}

main() {
    if [ $# -eq 0 ]; then
        echo "usage: $0 start|stop|restart ..."
        return 1
    fi

    for funcname in "$@"; do
        if [ "$(type -t $funcname)" != 'function' ]; then
            echo "'$funcname' not a shell function"
            return 1
        fi
    done

    for funcname in "$@"; do
        $funcname
    done
    return 0
}
main "$@"
```
### Установка и настройка wireguard
#### На сервере
```
sudo apt install wireguard
```
Создаем ключи для сервера и всех клиентов
```
wg genkey | sudo tee server_private.key | wg pubkey | sudo tee server_public.key
wg genkey | sudo tee client1_private.key | wg pubkey | sudo tee client1_public.key
```

Создаем конфигурационный файл сервера
```
sudo vim /etc/wireguard/wg0.conf
```
```
[Interface]
Address = 10.66.66.1/24
Address = fd42:42:42::1/64
SaveConfig = true
MTU = 1500
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE; ip6tables -A FORWARD -i wg0 -j ACCEPT; ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE; ip6tables -D FORWARD -i wg0 -j ACCEPT; ip6tables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
ListenPort = 58712
PrivateKey = PrivateKey

[Peer] 
#gateway
PublicKey = PublicKey
AllowedIPs = 10.66.66.64/26, fd42:42:42::/120

[Peer] 
#client1
PublicKey = PublicKey
AllowedIPs = 10.66.66.10/32, fd42:42:42::10/128

[Peer] 
#client2
PublicKey = PublicKey
AllowedIPs = 10.66.66.11/32, fd42:42:42::11/128
```
Все готово, осталось сделать 
```
sudo wg-quick up wg0
```

#### На клиенте

```
sudo apt install wireguard
```
Создаем конфигурационный файл клиента
```
sudo vim /etc/wireguard/wg0.conf
```

```
[Interface]
PrivateKey = PrivateKey
Address = 10.66.66.64/26
MTU = 1500
PostUp = iptables -t nat -A POSTROUTING -o wg0 -j MASQUERADE; iptables -A FORWARD -i eth0 -o wg0 -j ACCEPT; iptables -A FORWARD -i wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT; iptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostDown = iptables -t nat -D POSTROUTING -o wg0 -j MASQUERADE; iptables -D FORWARD -i eth0 -o wg0 -j ACCEPT; iptables -D FORWARD -i wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT; iptables -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

[Peer]
PublicKey = PublicKey
Endpoint = server-ip:58712
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 15
```
Все готово, осталось сделать 
```
sudo wg-quick up wg0
```
