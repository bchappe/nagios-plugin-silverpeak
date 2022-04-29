#!/usr/bin/perl 

#use strict;
use feature ":5.10";
no if ($] >= 5.018), 'warnings' => 'experimental::smartmatch';


use Data::Dumper;

use Net::SNMP;
use List::Compare;
use Getopt::Long qw(:config no_ignore_case bundling);
use Pod::Usage;
use POSIX;
use HTTP::CookieJar::LWP ();
use LWP::UserAgent       ();
use IO::Socket::SSL qw( SSL_VERIFY_NONE );
use JSON;

my $script = "check_silverpeak_ec.pl";
my $script_version = "1.0.1";

# codes de retour pour Nagios
my %status = ( 
  'OK'       => '0',
  'WARNING'  => '1',
  'CRITICAL' => '2',
  'UNKNOWN'  => '3'
);

my $auth = '/usr/local/nagios/secret/ec_config.cfg';

my %configParamHash = ();
open ( _FH, $auth ) or die "Unable to open config file: $!";
 
while ( <_FH> ) {
    chomp;
    s/#.*//;                # ignore comments
    s/^\s+//;               # trim leading spaces if any
    s/\s+$//;               # trim leading spaces if any
    next unless length;
    my ($_configParam, $_paramValue) = split(/\s*=\s*/, $_, 2);
    $configParamHash{$_configParam} = $_paramValue;
}
close _FH;



################################################# DEBUT DU SCRIPT PRINCIPAL (MAIN)

# analyser les arguments 
my ($ip, $port, $community, $type, $warn, $crit, $snmp_version, $user_name, $auth_password, $auth_prot, $priv_password, $priv_prot , $tun_filter) = parse_args();


my $session = "";
my $error = "";
my $return_state;
my $return_string;
my $oid_unitdesc;
my $oid;
my $value;
my $perf;
my $vjson;

my $api_user=$configParamHash{login};
my $api_pass=$configParamHash{pass};



if ( $snmp_version == 3 ) {   # SNMP V3 ?
  ($session, $error) = get_snmp_session_v3( $ip, $user_name, $auth_password, $auth_prot, $priv_password, $priv_prot, $port ); 
  }
else {                       # SNMPV2 ?
  ($session, $error) = get_snmp_session( $ip,  $community,$port,$snmp_version);
}

if ( $error ne "" ) {
  print "\n$error\n";
  exit(3);
}

# oids recherchés en SNMP
my $oid_label           = ".1.3.6.1.2.1.1.5.0"; # label
my $oid_cpu              = ".1.3.6.1.4.1.2021.10.1.3.1";    # CPU % usage sur 1 minute
my $oid_mem              = ".1.3.6.1.4.1.2021.4.11.0";    # mem en Ko libre
my $oid_memtotal        = ".1.3.6.1.4.1.2021.4.5.0";  # total mem en Ko installée


#selon le type d'info recherché      
      given ( lc($type) ) {
         when ("cpu") { ($return_state, $return_string) = get_health_value($oid_cpu, "CPU", "%"); }     
         when ("mem") { ($return_state, $return_string) = get_memhealth_value($oid_mem,$oid_memtotal, "Memory", "%"); }
         when ("disk") { ($return_state, $return_string) = get_disk_usage(); }
         when ("tunnels") { ($return_state, $return_string) = get_tunnels_status();}
      }
   

close_snmp_session($session);

# affiche sur stdout un retour pour le user  et exit avec le statuscode attendu par nagios
print $return_string."\n";
exit($status{$return_state});
################################################# FIN DU SCRIPT PRINCIPAL (MAIN)


############################## FONCTIONS ########################
# instancie une session SNMP   v2
sub get_snmp_session {
  my $ip = $_[0];
  my $community = $_[1];
  my $port = $_[2];
  my $version = $_[3];
  my ($session, $error) = Net::SNMP->session(
                              -hostname  => $ip,
                              -community => $community,
                              -port      => $port,
                              -timeout   => 10,
                              -retries   => 2,
                              -debug     => 0,
                              -version   => $version,
                              -translate => [-timeticks => 0x0]
                          );

  return ($session, $error);
} 

# instancie une session SNMP   v3
sub get_snmp_session_v3 {
  my $ip = $_[0];
  my $user_name = $_[1];
  my $auth_password = $_[2];
  my $auth_prot = $_[3];
  my $priv_password = $_[4];
  my $priv_prot = $_[5];
  my $port = $_[6];
  my ($session, $error) = Net::SNMP->session(
                              -hostname     => $ip,
                              -port         => $port,
                              -timeout      => 10,
                              -retries      => 2,
                              -debug        => 0,
                              -version      => 3,
                              -username     => $user_name,
                              -authpassword => $auth_password,
                              -authprotocol => $auth_prot,
                              -privpassword => $priv_password,
                              -privprotocol => $priv_prot,
                              -translate    => [-timeticks => 0x0] 
                          );
  return ($session, $error);
} 

# Renvoie l'info recherchée en bien formatée pour nagios
sub get_memhealth_value {
  my $label = $_[2];
  my $UOM   = $_[3];
      $oid = $_[0];
      $oid2 = $_[1];
 
  my $eclabel=get_snmp_value($session, $oid_label);
  $value = get_snmp_value($session, $oid);
  $value2 = get_snmp_value($session, $oid2);  
 # $value =~ s/\D*(\d+)\D*/$1/g;
  $value=100-(int($value*100/$value2));
  if ( $value >= $crit ) {
    $return_state = "CRITICAL";
    $return_string = $label . " is critical: " . $value . $UOM;
  } elsif ( $value >= $warn ) {
    $return_state = "WARNING";
    $return_string = $label . " is warning: " . $value . $UOM;
  } else {
    $return_state = "OK";
    $return_string = $label . " is OK: " . $value. $UOM;
  }

  $perf = "|'" . lc($label) . "'=" . $value . $UOM . ";" . $warn . ";" . $crit;
  $return_string = $return_state . ": " . $eclabel . "  " . $return_string . $perf;

  return ($return_state, $return_string);
} 

# Renvoie l'info recherchée en bien formatée pour nagios
sub get_health_value {
  my $label = $_[1];
  my $UOM   = $_[2];
      $oid = $_[0];
 
  my $eclabel=get_snmp_value($session, $oid_label);
  $value = get_snmp_value($session, $oid);
  
 # $value =~ s/\D*(\d+)\D*/$1/g;

  if ( $value >= $crit ) {
    $return_state = "CRITICAL";
    $return_string = $label . " is critical: " . $value . $UOM;
  } elsif ( $value >= $warn ) {
    $return_state = "WARNING";
    $return_string = $label . " is warning: " . $value . $UOM;
  } else {
    $return_state = "OK";
    $return_string = $label . " is OK: " . $value. $UOM;
  }

  $perf = "|'" . lc($label) . "'=" . $value . $UOM . ";" . $warn . ";" . $crit;
  $return_string = $return_state . ": " . $eclabel . "  " . $return_string . $perf;

  return ($return_state, $return_string);
} 

# Ferme la session snmp
sub close_snmp_session{
  my $session = $_[0];

  $session->close();
} 

sub get_tunnels_status{
  my $jar = HTTP::CookieJar::LWP->new;
  my $ua  = LWP::UserAgent->new(
    cookie_jar        => $jar,
    protocols_allowed => ['http', 'https'],
    timeout           => 5,
    ssl_opts => { 
        verify_hostname => 0, 
        SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE 
    }
    );
  my $uri = 'https://'.$ip.'/rest/json/login';
  my $json = '{"user":"'.$api_user.'","password":"'.$api_pass.'"}';
  my $req = HTTP::Request->new( 'POST', $uri );
  $req->header( 'Content-Type' => 'application/json' );
  $req->content( $json );
  my $res=$ua->request( $req );

  if ( $res->is_success() ) {    
       my $res2 = $ua->get( 'https://'.$ip.'/rest/json/tunnelsConfigAndState' );       
       if (! $res2->is_success() ) {return ("UNKNOWN", $res2->status_line());}      
       $vjson=decode_json($res2->content);
         
       %val=%$vjson;
        $value='';
        while( my ($k,$v) = each(%val) ) {
          if( $v->{'alias'} =~ m// ) {
		if ($tun_filter eq '' || $tun_filter eq 'ALL' || ($v->{'alias'} =~m/$tun_filter/i) )	  
		{				
			if ($v->{'status'} =~ m/down/i) { $value.=$v->{'alias'}." , ";}            
		}
          }
        }
      chop($value);chop($value);
       my $req = HTTP::Request->new( 'POST', 'https://'.$ip.'/rest/json/logout' );
       my $res=$ua->request( $req );
     
       $label='tunnelstatus';$UOM='';
        if ( $value ne '' ) {
          $return_state = "CRITICAL";
          $return_string = $label . " is critical: " . $value . " : down";
        }  else {
          $return_state = "OK";
          $return_string = $label . " is OK: Tunnels do DC are up";
        }

        $perf = "|'" . lc($label) . "'=" . $value . ";" . $warn . ";" . $crit;
        $return_string = $return_state . ": " . $eclabel . "  " . $return_string . $perf;

        return ($return_state, $return_string);           
  }
  else {
        return ("UNKNOWN", $res->status_line());      
  }
  
}

sub get_disk_usage{
  my $jar = HTTP::CookieJar::LWP->new;
  my $ua  = LWP::UserAgent->new(
    cookie_jar        => $jar,
    protocols_allowed => ['http', 'https'],
    timeout           => 5,
    ssl_opts => { 
        verify_hostname => 0, 
        SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE 
    }
    );
  my $uri = 'https://'.$ip.'/rest/json/login';
  my $json = '{"user":"'.$api_user.'","password":"'.$api_pass.'"}';
  my $req = HTTP::Request->new( 'POST', $uri );
  $req->header( 'Content-Type' => 'application/json' );
  $req->content( $json );
  my $res=$ua->request( $req );
  
  if ( $res->is_success() ) {
       my $res2 = $ua->get( 'https://'.$ip.'/rest/json/diskUsage' );  
       if (! $res2->is_success() ) {return ("UNKNOWN", $res2->status_line());}           
       $vjson=decode_json($res2->content);
       $value=$vjson->{'/'}->{'usedpercent'};       
       
       my $req = HTTP::Request->new( 'POST', 'https://'.$ip.'/rest/json/logout' );
       my $res=$ua->request( $req );
     
       $label='disk/';$UOM='%';
        if ( $value >= $crit ) {
          $return_state = "CRITICAL";
          $return_string = $label . " is critical: " . $value . $UOM;
        } elsif ( $value >= $warn ) {
          $return_state = "WARNING";
          $return_string = $label . " is warning: " . $value . $UOM;
        } else {
          $return_state = "OK";
          $return_string = $label . " is OK: " . $value. $UOM;
        }

        $perf = "|'" . lc($label) . "'=" . $value . $UOM . ";" . $warn . ";" . $crit;
        $return_string = $return_state . ": " . $eclabel . "  " . $return_string . $perf;

        return ($return_state, $return_string);           
  }
  else {
        return ("UNKNOWN", $res->status_line());      
  }
  
}

# wrapper pour récup une valeur SNMP
sub get_snmp_value{
  my $session = $_[0];
  my $oid = $_[1];

  my (%result) = %{get_snmp_request($session, $oid) || die ("SNMP service is not available on ".$ip) };

  if ( ! %result ||  $result{$oid} =~ /noSuch(Instance|Object)/ ) {
    $return_state = "UNKNOWN";

    print $return_state . ": OID $oid does not exist\n";
    exit($status{$return_state});
  }
  return $result{$oid};
} 

# recupere une valeur (OID) snmp
sub get_snmp_request{
  my $session = $_[0];
  my $oid = $_[1];

  my $sess_get_request = $session->get_request($oid);

  if ( ! defined($sess_get_request) ) {
    $return_state = "UNKNOWN";

    print $return_state . ": session get request failed\n";
    exit($status{$return_state});
  }

  return $sess_get_request;
} 

# recupere une table  snmp
sub get_snmp_table{
  my $session = $_[0];
  my $oid = $_[1];

  my $sess_get_table = $session->get_table(
                       -baseoid =>$oid
  );

  if ( ! defined($sess_get_table) ) {
    $return_state = "UNKNOWN";

    print $return_state . ": session get table failed for $oid \n";
    exit($status{$return_state});
  }
  return $sess_get_table;
}

#  Analyse les arguments passés
sub parse_args {
  my $ip            = "";       # snmp host
  my $port          = 161;      # snmp port
  my $snmp_version       = "2";      # snmp version
  my $community     = "public"; # only for v1/v2c
  my $user_name     = "public"; # v3
  my $auth_password = "";       # v3
  my $auth_prot     = "sha";    # v3 auth algo
  my $priv_password = "";       # v3
  my $priv_prot     = "aes";    # v3 priv algo
  my $type          = "cpu";
  my $warn          = 80;
  my $crit          = 90;  
  my $help          = 0;
  my $version       = 0;
  my $apiusername      = "admin";
  my $apipassword      = "";
  my $filter		= "ALL";


  pod2usage(-message => "Erreur: Pas d'arguments", -exitval => 3,  -sections => 'SYNOPSIS' ) if ( !@ARGV );

  GetOptions(
          'host|H=s'         => \$ip,
          'port|P=i'         => \$port,
          'snmp_version|V:s'      => \$snmp_version,
          'community|C:s'    => \$community,
          'type|T=s'         => \$type,
          'username|U:s'     => \$user_name,
          'authpassword|A:s' => \$auth_password,
          'authprotocol|a:s' => \$auth_prot,
          'privpassword|X:s' => \$priv_password,
          'privprotocol|x:s' => \$priv_prot,
          'warning|w:s'      => \$warn,
          'critical|c:s'     => \$crit,        
	  'filter|f:s'		=> \$filter,
          'help|h!'          => \$help,
          'version|v!'          => \$version,
  ) or pod2usage(-exitval => 3, -sections => 'OPTIONS' );

  if( $version )
  {
    print "$script version: $script_version\n";
    exit($status{'OK'});
  }
  pod2usage(-exitval => 3, -verbose => 3) if $help;

 

  return (    $ip, $port, $community, $type, $warn, $crit, $snmp_version, $user_name, $auth_password, $auth_prot, $priv_password, $priv_prot , $filter);
}

=head1 NAME

Silverpeak monitor

=head1 SYNOPSIS

=over 1

=item B<check_silverpeak_ec.pl -H -C -T [-w|-c|-S|-s|-U|-A|-a|-X|-x|-h|-y|-z|-f]>
:wq
=back

=head1 OPTIONS

=over 4

=item B<-H|--host>

STRING or IPADDRESS - Check interface on the indicated host

=item B<-P|--port>

INTEGER - SNMP Port on the indicated host, defaults to 161

=item B<-f|--filter>

STRING - Tunnel Filter (ALL for all tunnels to DC | 'label' to check only tunnels based on link identified by label)

=item B<-v|--snmp_version>

INTEGER - SNMP Version on the indicated host, possible values 1,2,3 and defaults to 2

=back

=head2 SNMP V3

=over 1

=item B<-U|--username>
STRING - username

=item B<-A|--authpassword>
STRING - authentication password

=item B<-a|--authprotocol>
STRING - authentication algorithm, defaults to sha

=item B<-X|--privpassword>
STRING - private password

=item B<-x|--privprotocol>
STRING - private algorithm, defaults to aes

=back

=head2 SNMP v1/v2c

=over 1

=item B<-C|--community>
STRING - Community-String for SNMP, defaults to public only used with SNMP version 1 and 2

=back

=head2 SNMP v1/v2c/3 - common

=over 1

=back


=head2 Other

=over

=item B<-T|--type>
STRING - cpu, mem, disk, tunnels

=item B<-w|--warning>
INTEGER - Warning threshold, applies to cpu, mem, disk

=item B<-c|--critical>
INTEGER - Critical threshold, applies to cpu, mem, disk

=item B<--version>
display script version; no check is performed.


=back

=head1 DESCRIPTION

Monitor un EC Silverpeak

=cut
