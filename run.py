#!flask/bin/python
from app import app
from os import system
system('sudo iptables -A INPUT -p tcp --dport 80 -j DROP')#  sudo iptables -t filter -A INPUT -p tcp --dport 80 -j ACCEPT
system('sudo iptables-save')
app.run(host="0.0.0.0", port="80",debug = True)