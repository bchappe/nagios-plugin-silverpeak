# nagios-plugin-silverpeak
nagios-plugin-silverpeak 
CPU
MEMORY
DISK
Tunnel State

Script for monitoring silverpeak with nagios core or nagios XI.
He use : 
- the API Silverpeak on central for auth
- SNMP 
https://IP-silverpeak/version/webclient/html/swagger/index.html

1 : Config and save a secret.cfg.
login = XXXX
pass = XXXX
You can modify the directory of secret.cfg in the line 30 with parameters $auth
my $auth = '/usr/local/nagios/ec_config.cfg';

2 : Config command nagios.
$USER1$/check_silverpeak_ec.pl -H $HOSTADDRESS$ -C $ARG1$ -T cpu -V2 -w 90 -c 95
$USER1$/check_silverpeak_ec.pl -H $HOSTADDRESS$ -T tunnels -f $ARG1$
$USER1$/check_silverpeak_ec.pl -H $HOSTADDRESS$ -T disk -w 90 -c 95
$USER1$/check_silverpeak_ec.pl -H $HOSTADDRESS$ -C $ARG1$ -T mem -V2 -w 90 -c 95

