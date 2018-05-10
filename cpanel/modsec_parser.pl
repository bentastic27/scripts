#!/usr/local/cpanel/3rdparty/bin/perl

use strict;
use warnings;
use File::Slurp;
use POSIX qw(strftime);
use List::MoreUtils qw(uniq);

# the perl equivalent of "if __name__ == '__main__'"
unless (caller){
    &user_interface;
}

sub user_interface {
    print "### ModSecurity Parser by Ben Healey ###\n\n";
    
    # get the modsec entries
    my @modsec_entries = get_modsec_entries(&get_log_location);
    print "Total ModSec errors: " . ($#modsec_entries + 1) . "\n\n";
    
    # while $exit != 1, run
    my $exit = 0;
    while ($exit != 1) {
        print "### Main Menu ###\n\n";
        # menu options
        print "Parse by...\n";
        print "Date: 1\n";
        print "Client IP: 2\n";
        print "Hostname: 3\n";
        print "URI: 4\n";
        print "Rule ID: 5\n\n";
        
        print "Other options\n";
        print "Summary: 7\n";
        print "Generate whitelist: 8\n";
        print "Exit: 0\n\n";
        
        # getting the input
        my $input = &get_user_input;
        
        if ($input eq "1"){ # parse by date
            print "### Parsing by Date ###\n\n";
            print "By today: 1\nEnter date: 2\nGo back: 0\n\n";
            $input = &get_user_input;
            
            if ($input eq "1") { # by today
                my $year = strftime "%Y", localtime;
                my $dom = strftime "%d", localtime;
                my $month = strftime "%b", localtime;
                
                @modsec_entries = parse_by_date(\@modsec_entries, $dom, $month, $year);
                print_entries(\@modsec_entries);
                
            } elsif ($input eq "2") { # enter date
                print "Enter date in YYYY-MMM-DD format.\n";
                print "Example: 2018-Mar-08\n\n";
                $input = &get_user_input;
                
                # checking input and doing
                if ($input =~ m/^\d{4}\-[A-Z][a-z]{2}\-\d{2}$/) {
                    my ($year, $month, $dom) = split '-', $input;
                    @modsec_entries = parse_by_date(\@modsec_entries, $dom, $month, $year);
                    print_entries(\@modsec_entries);
                
                } elsif ($input eq "0") { # exit
                    print "Going back\n\n";
                
                } else { # invalid input
                    print "Invalid date pattern, going back\n\n";
                }
                
            } elsif ($input eq "0") { # exit
                print "Going back\n\n";
            } else { # invalid
                print "Invalid option, going back\n\n"
            }
        
        } elsif ($input eq "2") { # parse by client
            print "### Parsing by Client IP Address ###\n\n";
            print "Enter IP address like 123.123.123.123.\n";
            $input = &get_user_input;
            
            # checking input and doing
            if ($input =~ m/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/) {
                @modsec_entries = parse_by_client(\@modsec_entries, $input);
                print_entries(\@modsec_entries);
            } elsif ($input eq "0") { # exit
                print "Going back\n\n";
            } else {
                print "Invalid IP address pattern, going back\n\n";
            }
            
        } elsif ($input eq "3") { # parse by hostname
            print "### Parsing by Hostname ###\n\n";
            print "Enter valid FQDN or IP address.\n";
            print "Example: whatever.com or 123.123.123.123\n";
            $input = &get_user_input;
            
            # checking input and doing
            if ($input =~ m/^[a-zA-Z0-9\.\-\_]+\.[a-zA-Z0-9]+$/) {
                @modsec_entries = parse_by_hostname(\@modsec_entries, $input);
                print_entries(\@modsec_entries);
            } elsif ($input eq "0") { # exit
                print "Going back\n\n";
            } else {
                print "Invalid IP or FQDN pattern, going back\n\n";
            }
            
        } elsif ($input eq "4") { # parse by uri
            print "### Parsing by URI ###\n\n";
            print "Enter valid URI like /wp-admin/ or /index.php or even /\n";
            $input = &get_user_input;
            
            # checking input and doing
            if ($input =~ m/^\/[a-zA-Z0-9\.\/\\\-]*$/){
                @modsec_entries = parse_by_uri(\@modsec_entries, $input);
                print_entries(\@modsec_entries);
            } elsif ($input eq "0") { # exit
                print "Going back\n\n";
            } else {
                print "Invalid URI pattern, going back\n\n";
            }
            
        } elsif ($input eq "5") { # parse by id
            print "### Parsing by Rule ID ###\n\n";
            print "Enter a valid ID like 12345\n";
            $input = &get_user_input;
            
            # checking input and doing
            if ($input =~ m/^\d{2,}$/){
                @modsec_entries = parse_by_id(\@modsec_entries, $input);
                print_entries(\@modsec_entries);
            } elsif ($input eq "0") { # exit
                print "Going back\n\n";
            } else {
                print "Invalid ID pattern, going back\n\n";
            }
        
        } elsif ($input eq "7") { # summary
            print_summary(\@modsec_entries);
                               
        } elsif ($input eq "8") { # generate whitelist
            print "### Generating whitelist ###\n\n";
            my $whitelist_string = gen_whitelist(\@modsec_entries);
            
            print "Show whitelist: 1\n";
            print "Write to file: /path/to/file.txt\n";
            print "(Protip: writing to an existing file overwrites it)\n\n";
            $input = &get_user_input;
            
            if ($input eq "1") {
                print "\n$whitelist_string\n";
            } elsif ($input eq "0") {
                print "Going back\n\n";
            } elsif (-f $input) {
                print "File already exists, overwrite? [y/n]\n";
                print "Cannot be undone!\n";
                if (&get_user_input eq "y"){
                    write_file($input, $whitelist_string);
                    print "Wrote whitelist to $input\n\n";
                }   
            } else {
                write_file($input, $whitelist_string);
                print "Wrote whitelist to $input\n\n";
            }
            
        } elsif ($input eq "0") { # exit
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
    print "### Current Entries ###\n\n";
    for (@{$entries}) {
        print " id $_->{id} // client $_->{client} // hostname $_->{hostname} // uri $_->{uri}\n";
    }
    print "\nCurrent total: " . @{$entries} . "\n";
    print "\n";
}

sub print_summary {
    my $modsec_entries = shift;
    
    # client array, unique client array, and client counts
    my @clients;
    for (@{$modsec_entries}) {
        push @clients, $_->{client} if (defined($_->{client}));
    }
    my @unique_clients = uniq @clients;
    my @client_counts;
    for my $client (@unique_clients) {
        my $count = 0;
        for (@clients) {
            $count += 1 if $client eq $_;
        }
        push @client_counts, {client => $client, count => $count};
    }
    
    # sort those while we're at it
    @client_counts = sort { $b->{count} <=> $a->{count} } @client_counts;
    
    print "### Client Data ###\n\n";
    print "Unique clients: ". @unique_clients . " \n\n";
    print "Highest 10:\n";
    print "$client_counts[$_]->{client}: $client_counts[$_]->{count}\n" for (0..9);
    print "\n";
    
    # hostname array, unique hostname array, and hostname counts
    my @hostnames;
    for (@{$modsec_entries}) {
        push @hostnames, $_->{hostname} if (defined($_->{hostname}));
    }
    my @unique_hostnames = uniq @hostnames;
    my @hostname_counts;
    for my $hostname (@unique_hostnames) {
        my $count = 0;
        for (@hostnames) {
            $count += 1 if $hostname eq $_;
        }
        push @hostname_counts, {hostname => $hostname, count => $count};
    }
    
    # sort those while we're at it
    @hostname_counts = sort { $b->{count} <=> $a->{count} } @hostname_counts;
    
    print "### Hostname Data ###\n\n";
    print "Unique hostnames: ". @unique_hostnames . " \n\n";
    print "Highest 10:\n";
    print "$hostname_counts[$_]->{hostname}: $hostname_counts[$_]->{count}\n" for (0..9);
    print "\n";
    
    # hostname array, unique hostname array, and hostname counts
    my @uris;
    for (@{$modsec_entries}) {
        push @uris, $_->{uri} if (defined($_->{uri}));
    }
    my @unique_uris = uniq @uris;
    my @uri_counts;
    for my $uri (@unique_uris) {
        my $count = 0;
        for (@uris) {
            $count += 1 if $uri eq $_;
        }
        push @uri_counts, {uri => $uri, count => $count};
    }
    
    # sort those while we're at it
    @uri_counts = sort { $b->{count} <=> $a->{count} } @uri_counts;
    
    print "### URI Data ###\n\n";
    print "Unique uris: ". @unique_uris . " \n\n";
    print "Highest 10:\n";
    print "$uri_counts[$_]->{uri}: $uri_counts[$_]->{count}\n" for (0..9);
    print "\n";
}

sub gen_whitelist {
    my $modsec_entries = shift;
    
    # get list of unique URIs
    my @unique_uris;
    for (@{$modsec_entries}) {
        push @unique_uris, $_->{uri} if (defined($_->{uri}));
    }
    @unique_uris = uniq @unique_uris;
    
    # generate list of hashes that contain the uri IDs
    my @whitelist_data;
    for my $uri (@unique_uris) {
        my @id_list = ();
        for my $entry (@{$modsec_entries}) {
            if (defined($entry->{uri}) && $entry->{uri} eq $uri) {
                push @id_list, $entry->{id};
            }
        }
        push @whitelist_data, {
            uri => $uri,
            ids => [@id_list]
        };
    }
    
    # generating the actual whitelist
    my $whitelist_string;
    for my $entry (@whitelist_data) {
        $whitelist_string .= "<LocationMatch \"$entry->{uri}\">\n";
        $whitelist_string .= "  SecRuleRemoveById";
        for my $rule_id (@{$entry->{ids}}) {
            $whitelist_string .= " " . $rule_id;
        }
        $whitelist_string .= "\n</LocationMatch>\n";
    }
    
    return $whitelist_string;
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

sub parse_by_client {
    my $modsec_entries = shift;
    my $client_ip = shift;
    my @parsed_entries;
    for (@{$modsec_entries}) {
        if (defined($_->{client}) && $_->{client} eq $client_ip) {
            push @parsed_entries, $_;
        }
    }
    return @parsed_entries;
}

sub parse_by_hostname {
    my $modsec_entries = shift;
    my $hostname = shift;
    my @parsed_entries;
    for (@{$modsec_entries}) {
        if (defined($_->{hostname}) && $_->{hostname} =~ m/$hostname$/) {
            push @parsed_entries, $_;
        }
    }
    return @parsed_entries
}

sub parse_by_uri {
    my $modsec_entries = shift;
    my $uri = shift;
    my @parsed_entries;
    for (@{$modsec_entries}) {
        if (defined($_->{uri}) && $_->{uri} eq $uri) {
            push @parsed_entries, $_;
        }
    }
    return @parsed_entries
}

sub parse_by_id {
    my $modsec_entries = shift;
    my $id = shift;
    my @parsed_entries;
    for (@{$modsec_entries}) {
        if (defined($_->{id}) && $_->{id} eq $id) {
            push @parsed_entries, $_;
        }
    }
    return @parsed_entries
}

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
