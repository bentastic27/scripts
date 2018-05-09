#!/usr/bin/perl
# change to /usr/local/cpanel/3rdparty/bin/perl on release

use strict;
use warnings;
use File::Slurp;
use POSIX qw(strftime);

# the perl equivalent of "if __name__ == '__main__'"
unless (caller){
    &user_interface;
}

sub user_interface {
    print "ModSecurity parser by Ben Healey\n\n";
    
    # get the modsec entries
    my @modsec_entries = get_modsec_entries(&get_log_location);
    print "Total ModSec errors: " . ($#modsec_entries + 1) . "\n\n";
    
    # while $exit != 1, run
    my $exit = 0;
    while ($exit != 1) {
        # menu options
        print "Parse by...\n";
        print "Date: 1\n";
        print "Client IP: 2\n";
        print "Hostname: 3\n";
        print "URI: 4\n";
        print "Rule ID: 5\n";
        print "Exit: 0\n\n";
        
        # getting the input
        my $input = &get_user_input;
        
        if ($input == 1){ # parse by date
            print "Parsing by date\n";
            print "By today: 1\nEnter date: 2\nGo back: 0\n\n";
            $input = &get_user_input;
            
            if ($input == 1) { # by today
                my $year = strftime "%Y", localtime;
                my $dom = strftime "%d", localtime;
                my $month = strftime "%b", localtime;
                
                @modsec_entries = parse_by_date(\@modsec_entries, $dom, $month, $year);
                print_entries(\@modsec_entries);
                
            } elsif ($input == 2) { # enter date
                print "Enter date in YYYY-MMM-DD format.\n";
                print "Example: 2018-Mar-08\n\n";
                $input = &get_user_input;
                
                # checking input and doing
                if ($input =~ m/^\d{4}\-[A-Z][a-z]{2}\-\d{2}$/) {
                    my ($year, $month, $dom) = split '-', $input;
                    @modsec_entries = parse_by_date(\@modsec_entries, $dom, $month, $year);
                    print_entries(\@modsec_entries);
                
                } else { # invalid input
                    print "Invalid date pattern, going back\n\n";
                }
                
            } elsif ($input == 0) { # exit
                print "Going back\n\n";
            } else { # invalid
                print "Invalid option, going back\n\n"
            }
        } elsif ($input == 2) { # parse by client
            parse_by_client();
        } elsif ($input == 3) { # parse by hostname
            parse_by_hostname();
        } elsif ($input == 4) { # parse by uri
            parse_by_uri();
        } elsif ($input == 5) { # parse by uri
            parse_by_id();
        } elsif ($input == 0) { # exit
            print "Bai\n";
            exit;
        } else { # invalid
            print "Invalid option, try again.\n\n"
        }
    }
}

sub get_user_input {
    print "Selection: ";
    my $user_input = <STDIN>;
    print "\n";
    chomp $user_input;
    return $user_input;
}

sub print_entries {
    my $entries = shift;
    print "Current entries:\n";
    for (@{$entries}) {
        print "id $_->{id} // client $_->{client} // uri $_->{uri}\n";
    }
    print "\nCurrent total: " . @{$entries} . "\n";
    print "\n";
}

sub parse_by_date {
    my $modsec_entries = shift;
    my $dom = shift;
    my $month = shift;
    my $year = shift;
    
    # new array with parsed entries to be returned
    my @parsed_entries;
    
    # looping over and getting entries with matched dates
    for (@{$modsec_entries}) {
        if (defined($_->{date}) && $_->{date} =~ m/$month\s$dom\s[0-9:\.]+\s$year/) {
            push @parsed_entries, $_;
        }
    }
    
    return @parsed_entries;
}

sub parse_by_client {}

sub parse_by_hostname {}

sub parse_by_uri {}

sub parse_by_id {}

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
