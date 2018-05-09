#!/usr/bin/perl
# change to /usr/local/cpanel/3rdparty/bin/perl on release

use strict;
use warnings;
use File::Slurp;
use Data::Dumper;

print Dumper(get_modsec_entries(&get_log_location));

sub get_log_location {
    if ($#ARGV != -1) {
        if (-f $ARGV[0]){
            return $ARGV[0];
        } else {
            die "ERROR: $ARGV[0] is not a file\n";
        }
    } elsif (-f "/etc/apache2/logs/error_log") {
        return "/etc/apache2/logs/error_log";
    } elsif (-f "/usr/local/apache/logs/error_log") {
        return "/usr/local/apache/logs/error_log";
    } elsif (-f "/var/log/apache2/error_log") {
        return "/var/log/apache2/error_log";
    } else {
        die "ERROR: No error log found";
    }
}

sub get_modsec_entries {
    my $error_log_location = shift;
    my @modsec_entries;
    
    my $modsec_regex = qr/
        ^\[\w{3}\s([\d\w:\.\s]+)\]
        .+\[:error\].+
        \[client\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d{0,6}\].*
        ModSecurity:\sAccess\sdenied.*
        \[id\s"(\d+)"\].*
        \[hostname\s"([a-zA-Z0-9\-\._]+)"\].*
        \[uri\s"([a-zA-Z0-9\\\-\_\.\?%\/]+)"\].*$
    /x;
    
    for my $line (read_file($error_log_location)){
        chomp $line;
        # making sure the line has the needed criteria
        if ($line =~ m/^.*\[:error\].*\[client.*ModSecurity.*\[id.*\[hostname.*\[uri.*$/) {
            # getting the relavent data and pushing to list
            $line =~ m/$modsec_regex/;
            push @modsec_entries, {
                date => $1,
                client => $2,
                id => $3,
                hostname => $4,
                uri => $5
            };
        }
    }
    
    return @modsec_entries;
}
