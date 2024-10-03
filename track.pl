#!/usr/bin/env perl

use strict;
use warnings;
use diagnostics;

use feature q/state/;

use Irssi;
use MIME::Base64 qw(encode_base64 decode_base64);
use English '-no_match_vars';
use Data::Dumper;
use ReadonlyX;
use DateTime;
use DBI;

Readonly::Scalar my $SCRIPT_NAME     => 'track';
Readonly::Scalar my $NAME_BUFFER_MAX => 25;
Readonly::Scalar my $EMPTY_STRING    => qw{};
Readonly::Scalar my $ZERO            => 0;
Readonly::Scalar my $SUCCESS         => 1;
Readonly::Scalar my $FAILURE         => 0;
Readonly::Scalar my %DB              => {};

our $VERSION = '2.4';
use vars qw($VERSION %IRSSI);

%IRSSI = (
    authors     => 'Ziddy',
    contact     => 'DALnet',
    name        => $SCRIPT_NAME,
    description => 'Keeps track of users by building a database'
      . 'of online, joining and nickchanges. Regex-cabable'
      . 'for the most part, AKA import available. Search by'
      . 'ident, nick or host',
    license => 'Public Domain',
    url     => 'none',
);

Readonly::Hash my %SCRIPT_OPTS => (
    track_file       => { name => 'track_file',       value => Irssi::get_irssi_dir() . '/track.lst' },
    track_quiet      => { name => 'track_quiet',      value => $ZERO },
    track_sql_enable => { name => 'track_sql_enable', value => $ZERO },
    track_raw_enable => { name => 'track_raw_enable', value => $ZERO },
    track_sql_host   => { name => 'track_sql_host',   value => $EMPTY_STRING },
    track_sql_port   => { name => 'track_sql_port',   value => $EMPTY_STRING },
    track_sql_user   => { name => 'track_sql_user',   value => $EMPTY_STRING },
    track_sql_pass   => { name => 'track_sql_pass',   value => $EMPTY_STRING },
    track_sql_db     => { name => 'track_sql_db',     value => $EMPTY_STRING },
    track_sql_table  => { name => 'track_sql_table',  value => $EMPTY_STRING },
);

my $quiet_mode        = $ZERO;
my $name_buffer_count = $ZERO;
my $sql               = $ZERO;
my $pulling_whois     = $ZERO;

my $active_server;
my $active_nick;
my $active_uid;

my ($sql_host, $sql_pass, $sql_user, $sql_table, $sql_port, $sql_db);
my $dbh;

track_banner();

Irssi::command_bind($SCRIPT_NAME => \&track);

Irssi::signal_add('message join',       'joining');
Irssi::signal_add('message nick',       'nchange');
Irssi::signal_add('message irc notice', 'notice');

Irssi::signal_add_first('event 311', 'whois_signal');
Irssi::signal_add_last('event 319', 'process_chans');
Irssi::signal_add_last('setup changed', 'init');
init();

sub init {
    my $connect_msg;
    my $track_file;

    $DB{limits}{name_buffer} = $NAME_BUFFER_MAX;
    $DB{count}{raw}{name_buffer} = $ZERO;
    $DB{count}{sql}{name_buffer} = $ZERO;
    $DB{count}{raw} = $ZERO;
    $DB{count}{sql} = $ZERO;

    Irssi::settings_add_bool($SCRIPT_NAME,      $SCRIPT_OPTS{track_quiet}{name},      $SCRIPT_OPTS{track_quiet}{value});
    Irssi::settings_add_bool($SCRIPT_NAME, $SCRIPT_OPTS{track_sql_enable}{name}, $SCRIPT_OPTS{track_sql_enable}{value});
    Irssi::settings_add_bool($SCRIPT_NAME, $SCRIPT_OPTS{track_raw_enable}{name}, $SCRIPT_OPTS{track_raw_enable}{value});
    Irssi::settings_add_str($SCRIPT_NAME,        $SCRIPT_OPTS{track_file}{name},       $SCRIPT_OPTS{track_file}{value});
    Irssi::settings_add_str($SCRIPT_NAME,    $SCRIPT_OPTS{track_sql_host}{name},   $SCRIPT_OPTS{track_sql_host}{value});
    Irssi::settings_add_str($SCRIPT_NAME,    $SCRIPT_OPTS{track_sql_user}{name},   $SCRIPT_OPTS{track_sql_user}{value});
    Irssi::settings_add_str($SCRIPT_NAME,    $SCRIPT_OPTS{track_sql_pass}{name},   $SCRIPT_OPTS{track_sql_pass}{value});
    Irssi::settings_add_str($SCRIPT_NAME,    $SCRIPT_OPTS{track_sql_port}{name},   $SCRIPT_OPTS{track_sql_port}{value});
    Irssi::settings_add_str($SCRIPT_NAME,   $SCRIPT_OPTS{track_sql_table}{name},  $SCRIPT_OPTS{track_sql_table}{value});
    Irssi::settings_add_str($SCRIPT_NAME,      $SCRIPT_OPTS{track_sql_db}{name},     $SCRIPT_OPTS{track_sql_db}{value});

    $track_file = Irssi::settings_get_str($SCRIPT_OPTS{track_file}{name});

    if ($track_file && -e $track_file) {
        Readonly my $FILE_SIZE       => 7;
        Readonly my $KILOBYTE => 1024;

        my $db_size  = sprintf '%.02f KB', (stat $track_file)[$FILE_SIZE] / $KILOBYTE;
        $connect_msg = "%NLoaded track database: '%G$track_file%N' (Size: %C$db_size%N)";
    }

    $quiet_mode = Irssi::settings_get_bool($SCRIPT_OPTS{track_quiet}{name});

    $connect_msg = $quiet_mode ? '(Quiet: %ROFF%N)' : '(Quiet: %GON%N)';

    $sql_host  = Irssi::settings_get_str($SCRIPT_OPTS{track_sql_host}{name});
    $sql_user  = Irssi::settings_get_str($SCRIPT_OPTS{track_sql_user}{name});
    $sql_pass  = Irssi::settings_get_str($SCRIPT_OPTS{track_sql_pass}{name});
    $sql_port  = Irssi::settings_get_str($SCRIPT_OPTS{track_sql_port}{name});
    $sql_table = Irssi::settings_get_str($SCRIPT_OPTS{track_sql_table}{name});
    $sql_db    = Irssi::settings_get_str($SCRIPT_OPTS{track_sql_db}{name});

    if (Irssi::settings_get_str($SCRIPT_OPTS{track_sql_enable}{name})) {
        if (check_sql_info()) {
            sql_init();
            my $sth = $dbh->prepare("SELECT COUNT(*) FROM $sql_table;");
            $sth->execute;
            $DB{count}{sql} = $sth->fetchrow();
        }
    } else {
        Irssi::print('%RSQL mode not active%N');
    }

    init_db();

    Irssi::print("$connect_msg\n");
    Irssi::print(' Raw DB: %G' . $DB{count}{raw} . '%N');
    Irssi::print(' SQL DB: %G' . $DB{count}{sql} . '%N ');
    Irssi::print('NBuffer: %G' . $DB{limits}{name_buffer} . '%N  ');

    return $SUCCESS;
}

sub whois_signal {
    my ($server, $data, $txtserver) = @_;
    my ($me, $nick, $ident, $host, $unused, $real_name) = split q{ }, $data;
    my $registered = $ZERO;
    my $unique_id = get_unique_id($nick, $ident, $host);
    my $chans;

    Irssi::print('%RDEBUG');
    print Dumper(Irssi::active_server->nicks_get_same($nick));
    Irssi::print('=======%N');
    $active_server = $server;
    $active_uid    = $unique_id;

    $nick = conv($nick);
    $ident =~ s/^~//xms;
    $ident = conv($ident);

    $real_name =~ s/^://xms;
    $real_name =~ s/[^ -~]//gxms;

    Irssi::print("derder: $data");

    if ($data =~ /has identified for this nick/xms) {
        $registered = 1;
    }

    if ($data =~ /channels/xms) {
        ($unused, my $channels) = split /$data/xms, qw{:};
        my $sth = $dbh->prepare("SELECT `channels` FROM $sql_table WHERE unique_id = ?")
                    or carp("Unable to prepare statement: ${dbh->errstr}");

        $sth->execute($unique_id);

        my @result = $sth->fetchrow_array();

        if (!$result[0] || $result[0] =~ /None/xms) {
            $sth = $dbh->prepare("UPDATE $sql_table SET channels = ? WHERE unique_id = ?");
            $sth->execute($channels, $unique_id);
        }
    }

    process_info($server, $nick, $ident, $host, $real_name, $chans,
        $registered);

    return $SUCCESS;
}

sub joining {
    my ($server, $channame, $unick, $host) = @_;
    $unick = conv($unick);
    my @spl   = split /@/xms, $host;
    my $ident = $spl[0];
    my $mask  = $spl[1];

    $ident =~ s/^~//xms;
    $ident = conv($ident);

    $active_server = $server;
    $active_nick   = $unick;

    if ($server->{nick} eq $unick) {
        return;
    }

    Irssi::active_server->send_raw("WHOIS $unick");
    Irssi::active_server->send_raw("nickserv info $unick");

    return $SUCCESS;
}

sub nchange {
    my ($server, $newnick, $oldnick, $host) = @_;
    $newnick = conv($newnick);
    my @spl   = split /@/xms, $host;
    my $ident = $spl[0];
    my $mask  = $spl[1];
    ($ident = $ident) =~ s/^~//xms;
    $ident         = conv($ident);
    $active_server = $server;
    $active_nick   = $newnick;

    Irssi::active_server->send_raw("WHOIS $newnick");
    Irssi::active_server->send_raw("nickserv info $newnick");

    return $SUCCESS;
}

sub process_info {
    my ($server, $nick, $ident, $mask, $real_name, $channels, $registered) = @_;
    $channels   //= 'None';
    $registered //= $ZERO;

    if (Irssi::settings_get_str($SCRIPT_OPTS{track_raw_enable}{name})) {
        $name_buffer_count++;

        if (!exists $DB{$nick}) {
            $DB{$nick}{ident} = $ident;
            $DB{$nick}{mask}  = $mask;

            if (!$quiet_mode) {
                Irssi::print("%GADDED $nick;$ident;$mask");
            }
        } else {
            if (!$quiet_mode) {
                Irssi::print("%REXIST $nick;$ident;$mask");
            }
        }

        do_buffer_checks();
    }

    if (Irssi::settings_get_bool($SCRIPT_OPTS{track_sql_enable}{name})) {
        my $unique_id = get_unique_id($nick, $ident, $mask);
        my $sql_query = <<'SQL';
            INSERT IGNORE INTO $sql_table
                (`nickname`, `ident`, `hostname`, `date_first_seen`, `date_last_seen`, `real_name`, `registered`, `bot`, `unique_id`)
            VALUES (?,?,?,?,?,?,?,?,?) 
                ON DUPLICATE KEY UPDATE `date_last_seen` = ?, `real_name` = ?, `registered` = ?;
SQL

        my $sth = $dbh->prepare($sql_query) 
            or carp('Can\'t prepare statement: ' . $dbh->errstr);

        $sth->execute(
            $nick, $ident, $mask, get_sql_time(), get_sql_time(), $real_name, $registered, $ZERO, $unique_id, get_sql_time(), $real_name, $registered
        ) or carp("Can't insert entry: " . $dbh->errstr);
    }

    return $SUCCESS;
}

sub get_unique_id {
    my ($unick, $ident, $host, $channel) = @_;

    if ($channel) {
        return encode_base64("$unick:$ident:$host:$channel");
    }

    return encode_base64("$unick:$ident:$host");
}

sub track {
    my $match;
    my $input = $_[0];

    chomp ($input);
    print "INPUT: $input\n";

    my @spl = split (/\s/, $input);
    my $type;

    if ($spl[0]) {
        $type = $spl[0];
    } else {
        help();
        return;
    }

    if ($type eq 'set') {
        track_options($input);
        return;
    }

    if ($type eq 'gather') {
        namechan();
        return;
    }

    if ($type eq 'import_raw') {
        raw_to_sql();
        return;
    }

    if ($type eq 'debug') {
        my @tests = (
            '"^^DumbNick^^', '[[^^bitchtits^^]]',
            '[][][]',        '\fugmuffin\\',
            'okthatsgood',   '@@[[lol]]##'
        );
        foreach my $test (@tests) {
            my $result = do_conv($test);
            Irssi::print("%GTesting : %N$test%N");
            Irssi::print("%GGot back: %R$result%N");
        }
    }

    if ($type eq 'count') {
        my $which = $spl[1];
        $which //= 'raw';
        if ($which eq 'raw') {
            Irssi::print("%RRAW%N Database Entries%N: " . $DB{count}{raw} . " users");
        } elsif ($which eq 'sql') {
            my $sth = $dbh->prepare("SELECT COUNT(*) FROM $sql_table");
            $sth->execute();
            my $dbcount = $sth->fetchrow();
            $sth = $dbh->prepare('SELECT COUNT(*) FROM track_data');
            $sth->execute();
            my $chancount = $sth->fetchrow();
            Irssi::print(
                "%GSQL Database Entries%N: $dbcount users - $chancount channels"
            );
        }
        return;
    } elsif ($type eq 'quiet') {
        $quiet_mode = $quiet_mode ? 0 : 1;
        Irssi::print("%GQuiet mode set to $quiet_mode");
        Irssi::settings_set_bool('track_quiet', $quiet_mode);
        return;
    } elsif ($type eq 'help') {
        help();
        return;
    } elsif ($type eq 'search') {
        my ($unused, $which, $field, $term) = split / /xms, $input;
        my $pcr = qr/$term/;

        if ($which eq "raw") {
            open my $fh, '<', $track_file;
            my @list = <$fh>;
            close $fh;

            foreach my $line (@list) {
                chomp ($line);
                my ($line_nick, $line_ident, $line_host) = split /;/xms, $line;

                if ($field eq 'host') {
                    if ($line_host =~ /$pcr/) {
                        Irssi::print("%GHost[%n$term%G]%n: $line_nick used $line_ident on -> %_$line_host%_ <-");
                        $match = 1;
                    }
                } elsif ($field eq 'nick') {
                    if ($line_nick =~ /$pcr/) {
                        Irssi::print("%GNick[%n$term%G]%n: -> %_$line_nick%_ <- used $line_ident on $line_host");
                        $match = 1;
                    }
                } elsif ($field eq 'ident') {
                    if ($line_ident =~ /$pcr/) {
                        Irssi::print("%GIdent[%n$term%G]%n: $line_nick used -> %_$line_ident%_ <- on $line_host");
                        $match = 1;
                    }
                } elsif ($field eq 'all') {
                    if ($line =~ /$pcr/) {
                        Irssi::print("%GALL[%n$term%G]%N: -> $line_nick used $line_ident on $line_host <-");
                        $match = 1;
                    }
                } else {
                    Irssi::print("%RUnknown search field%N");
                    last;
                }
            }
        } else {
            if ($field eq 'channel') {
                $term =~ s/[\$\@\+]//g;
                Irssi::print("Checking for $term channel");
                my $sth = $dbh->prepare(
                    'SELECT nickname,ident,hostname,channel FROM track JOIN track_data USING (unique_id) WHERE track_data.channel LIKE ?'
                );
                $sth->execute($term);
                while (my @row = $sth->fetchrow_array()) {
                    Irssi::print("@row");
                }
            }
        }
    }

    if (!$match) {
        Irssi::print('%RNo data to return');
    }

    return $SUCCESS;
}

sub uniq {
    my %seen;
    grep !$seen{$_}++, @_;
    return $SUCCESS;
}

sub namechan {
    my $count = $ZERO;

    foreach my $serv (Irssi::channels()) {
        my $curserv = $serv->{server}->{tag};
        my $sth     = $dbh->prepare(
            "UPDATE `$sql_table` SET date_last_seen = ?, real_name = ?, servers = ? WHERE unique_id = ?"
        );
        foreach my $nname ($serv->nicks()) {
            my $unick = conv($nname->{nick});
            open my $fh, '<', $track_file;
            my @list = <$fh>;
            close $fh;
            my $real_name = $nname->{realname};
            my @temp      = split /@/, $nname->{host};
            my $ident     = $temp[0];
            my $host      = $temp[1];
            my $unique_id = get_unique_id($unick, $ident, $host);
            my $servers   = Irssi::active_server->{real_address};
            $ident     =~ s/^~//xms;
            $real_name =~ s/[^ -~]//xmsg;    # clear all non-printable characters

            if (!grep /$unick;$ident;$host/xms, @list) {
                Irssi::active_server->send_raw('WHOIS ' . $unick);
                $count++;
            } else {
                if (Irssi::settings_get_bool('track_sql_enable')) {
                    $sth->execute(get_sql_time(), $real_name, $servers, $unique_id);
                }
                Irssi::print("%RAlready gathered $unick") if !$quiet_mode;
            }
        }
    }
    Irssi::print("%GGathering complete - Added $count new entries");

    return $SUCCESS;
}

sub conv {
    my $data = $_[0];
    return if !$data;

    ($data = $data) =~ s/\]/~~/g;
    ($data = $data) =~ s/\[/@@/g;
    ($data = $data) =~ s/\^/##/g;
    ($data = $data) =~ s/\\/&&/g;

    return $data;
}

sub unconv {
    my $data = $_[0];
    return if !$data;

    ($data = $data) =~ s/~~/\]/g;
    ($data = $data) =~ s/@@/\[/g;
    ($data = $data) =~ s/##/\^/g;
    ($data = $data) =~ s/%%/\\/g;

    return $data;
}

sub do_conv {
    my @data = split //xms, $_[0];

    return if scalar @data < 1;

    my %conversions = (
        '~~' => ']',
        '@@' => '[',
        '##' => '^',
        '%%' => '\\',
        ']'  => '~~',
        '['  => '@@',
        '^'  => '##',
        '\\' => '%%',
    );

    for (my $i = 0; $i < scalar @data - 1; $i++) {
        foreach my $key (keys %conversions) {
            my $value = $conversions{$key};
            $data[$i] =~ s/\Q$key\E/\Q$value\E/gxms;
        }
    }

    return join ('', @data);
}

#Messy for now
sub importAKA {
    my $input = $_[0];
    if (-e $input) {
        open (my $fh, '<', $input);
        my @list = <$fh>;
        close ($fh);
        my $ip = $ZERO;
        my ($string, $import);
        foreach my $line (@list) {
            chomp ($line);
            my @nicks;
            if ($line =~ /(.*?)@(.*+)/gxms) {
                $ip = $2;
            } elsif ($line =~ /(.*)~/gxms) {
                my @nicksplit = split (/~/xms, $1);
                foreach my $ns (@nicksplit) {
                    push (@nicks, $ns);
                }
            }
            foreach my $nick (@nicks) {
                my $snick = conv($nick);
                if ($snick and $ip) {
                    if (length ($snick) > 1 and length ($ip) > 1) {
                        $string .= "$snick;AKAImport;$ip;;;";
                    }
                }
            }
        }
        my @arrn = split (/;;;/xms, $string);
        open (my $fh2, '>>', $track_file);
        foreach my $out (@arrn) {
            if (length ($out) > 1) {
                $out =~ s/\r//g;
                print $fh2 "$out\n";
                $import++;
            }
        }
        close ($fh2);
        Irssi::print("%GImported $import users into the database%n");
    }
}

sub sql_init {
    my $create_database   = "CREATE DATABASE IF NOT EXISTS `$sql_db`;";
    my $create_main_table = "CREATE TABLE IF NOT EXISTS `$sql_table` (
    `id` int(9) NOT NULL AUTO_INCREMENT,
    `nickname` varchar(255) CHARACTER SET utf8 NOT NULL,
    `ident` varchar(255) CHARACTER SET utf8 NOT NULL,
    `hostname` varchar(255) CHARACTER SET utf8 NOT NULL,
    `real_name` varchar(255) CHARACTER SET utf8 DEFAULT NULL,
    `registered` tinyint(1) DEFAULT 0,
    `bot` tinyint(9) DEFAULT 0,
    `date_first_seen` datetime DEFAULT NULL,
    `date_last_seen` datetime DEFAULT NULL,
    `date_registered` datetime DEFAULT NULL,
    `date_modified` timestamp NULL DEFAULT NULL ON UPDATE current_timestamp(),
    `unique_id` varchar(255) CHARACTER SET utf8 NOT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `UNIQUE` (`unique_id`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

    CREATE TABLE IF NOT EXISTS`track_data` (
    `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
    `server` varchar(100) NOT NULL,
    `channel` varchar(100) NOT NULL,
    `date_added` timestamp NULL DEFAULT NULL ON UPDATE current_timestamp(),
    `unique_id` varchar(255) NOT NULL COMMENT 'users unique id',
    `unique_data_id` varchar(255) NOT NULL COMMENT 'users unique id with chan/serv',
    PRIMARY KEY (`id`),
    UNIQUE KEY `UNIQUE` (`unique_data_id`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";

    chomp (my $t_out =
          `mysql -e 'SELECT * FROM mysql.user' -u $sql_user -p'$sql_pass' 2>&1`
    );

    if ($t_out !~ /command denied/i) {
        Irssi::print(
            "%BUser not found, assuming first run. Creating MySQL user %Y'$sql_user'%N"
        );
        Irssi::print(
            "%Bwith all privileges on newly created table %Y'$sql_table'%N in newly"
        );
        Irssi::print("%Bcreated database %Y'$sql_db'%N");

        chomp ($t_out = `mysql -e '$create_database' 2>&1`);
        $t_out = "%GGood%N" if length $t_out < 3;
        Irssi::print("%YDatabase creation result: $t_out");

        chomp ($t_out = `mysql -e 'use "$sql_db"; $create_main_table' 2>&1`);
        $t_out = "%GGood%N" if length $t_out < 3;
        Irssi::print("%YTable creation result: $t_out");

        chomp (
            $t_out = `mysql -e 'use "$sql_db";
            GRANT ALL PRIVILEGES ON $sql_table.* TO "$sql_user"@"$sql_host" IDENTIFIED BY "$sql_pass";
            GRANT ALL PRIVILEGES ON track_data.* TO "$sql_user"@"$sql_host" IDENTIFIED BY "$sql_pass";
            FLUSH PRIVILEGES;' 2>&1`
        );
        $t_out = "%GGood%N" if length $t_out < 3;
        Irssi::print("%YPrivilege creation result: $t_out");
    }

    $dbh = DBI->connect("DBI:MariaDB:$sql_db", $sql_user, $sql_pass)
      or die "Unable to connect to SQL database: $CHILD_ERROR\n";
    Irssi::print("%GSuccessfully connected to database %C$sql_db%N");
    Irssi::print('%G*%R*%Y*%B*%N SQL Mode fully activated!!! %B*%Y*%R*%G*%N');
    Irssi::settings_set_bool('track_sql_enable', 1);

    return $SUCCESS;
}

sub track_options {
    my $input = $_[0];
    $input =~ s/set //;

    my ($command, $argument, $value) = split / /, $input;

    if ($command eq 'sql' && !$argument) {
        if (check_sql_info()) {
            $sql = 1;
            Irssi::print('%GSQL mode successfully activated');
            sql_init();
        } else {
            my @missing;
            foreach my $opt ('host', 'db', 'table', 'user', 'pass', 'port') {
                if (!Irssi::settings_get_str("track_sql_$opt")) {
                    push (@missing, $opt);
                }
            }
            Irssi::print(
                '%RSQL mode cannot be enabled until required information has been supplied via \'/track set sql <arg> <val>\''
            );
            Irssi::print('%RMissing SQL information: ' . join ', ', @missing);
        }
    } elsif ($command eq 'sql' && $argument =~ /(host|db|user|pass|port|table)/) {
        my $setting = $1;
        if (!$value) {
            Irssi::print("You must supply a value to set option '$argument'");
        }
        if (Irssi::settings_get_str("track_sql_$setting")) {
            Irssi::settings_set_str("track_sql_$setting", $value);
            Irssi::print("Overwrote current $setting value");
        } else {
            Irssi::settings_set_str("track_sql_$setting", $value);
            Irssi::print("$setting has been set");
        }
    } elsif ($command eq 'raw') {
        my $current_status = Irssi::settings_get_bool('track_raw_enable');
        Irssi::settings_set_bool('track_raw_enable', $current_status ? 0 : 1);
        Irssi::print(
            "Raw mode set to: " . ($current_status ? "%GOFF%N" : "%RON%N"));
    } else {
        Irssi::print('%RUnknown directive passed to \'set\'');
    }

    return $SUCCESS;
}

sub check_sql_info {
    my $passed = $ZERO;

    ($sql_host, $sql_user, $sql_pass, $sql_port, $sql_table, $sql_db) = (
        Irssi::settings_get_str('track_sql_host'),
        Irssi::settings_get_str('track_sql_user'),
        Irssi::settings_get_str('track_sql_pass'),
        Irssi::settings_get_str('track_sql_port'),
        Irssi::settings_get_str('track_sql_table'),
        Irssi::settings_get_str('track_sql_db'),
    );

    if (   length $sql_host > 1
        && length $sql_user > 1
        && length $sql_pass > 1
        && length $sql_port > 1
        && length $sql_table > 1
        && length $sql_db > 1) {
        $passed = 1;
    }

    return $passed;
}

sub get_sql_time {
    my $dt = DateTime->from_epoch(epoch => time ());
    return $dt->strftime('%Y-%m-%d %H:%M:%S');
}

sub file_to_array {
    my ($file_path, $arr_ref) = @_;
    my $contents;
    local $/;

    open my $fh, '<', $file_path
      or warn "Couldn't open file '$file_path': $OS_ERROR\n";

    $contents = <$fh>;
    @$arr_ref = split /[\r\n]/, $contents;

    close $fh;

    return $SUCCESS;
}

sub load_raw {
    my @temp_entries;

    file_to_array(Irssi::settings_get_str('track_file'), \@temp_entries);

    foreach my $entry (@temp_entries) {
        chomp $entry;
        my ($nick, $ident, $host) = split /;/, $entry;

        $DB{$nick}{ident} = $ident;
        $DB{$nick}{host}  = $host;
        $DB{count}{raw}++;
    }
}

sub load_sql {
    if (check_sql_info()) {
        my $sql_table = Irssi::settings_get_str('track_sql_table');
        my $sth = $dbh->prepare("SELECT * FROM $sql_table");
        $sth->execute();

        while (my $row_ref = $sth->fetchrow_arrayref) {
            my ($nick, $ident, $host, $real, $reg, $bot, $dfs,  $dls,   $dr,   $dm,   $uuid) = @$row_ref;
            $DB{$nick}{real}       = $real;
            $DB{$nick}{registered} = $reg;
            $DB{$nick}{bot}        = $bot;
            $DB{$nick}{date_first} = $dfs;
            $DB{$nick}{date_last}  = $dls;
            $DB{$nick}{date_reg}   = $dr;
            $DB{$nick}{date_mod}   = $dm;
            $DB{$nick}{uuid}       = $uuid;
            $DB{count}{sql}++;
        }
    }
}

sub init_db {
    #    do_backups();
    load_raw();
    load_sql();

    Irssi::print(
        "Initialized the database with %Y" . $DB{count}{raw} .
        "%N %RRAW%N entries, and %G" . $DB{count}{sql} . "%N %BSQL%N entries"
    );

    return $SUCCESS;
}

sub raw_to_sql {
    open my $fh, '<', Irssi::settings_get_str('track_file');
    my @list = <$fh>;
    close $fh;

    my $sth = $dbh->prepare(
        "INSERT INTO $sql_table (nickname, ident, hostname, date_first_seen, date_last_seen, real_name, registered, channels, servers, bot, unique_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    ) or warn "Can't prepare statement: $CHILD_ERROR ($dbh->errstr)";

    foreach my $entry (@list) {
        my ($unick, $ident, $host) = split (';', $entry);
        my ($date_first_seen, $date_last_seen) =
          (get_sql_time(), get_sql_time());
        my ($registered, $bot) = (0, 0);
        my $real_name = 'IMPORTED';
        my $channels  = '';
        my $servers   = '';
        my $unique_id = get_unique_id($unick, $ident, $host);

        $sth->execute(
            $unick,           $ident,          $host,
            $date_first_seen, $date_last_seen, $real_name,
            $registered,      $channels,       $servers,
            $bot,             $unique_id,
          )
          or warn "Can't execute prepared statement: $CHILD_ERROR ($dbh->errstr)";
    }
}

sub process_chans {
    my ($server, $chans, $server_real_address) = @_;

    if ($chans =~ /.*? .*? :#/) {
        my @spl       = split (/:/xms, $chans);
        my $chanlist  = $spl[1];
        my @chansplit = split (' ', $chanlist);

        foreach my $channel (@chansplit) {
            my $temp = decode_base64($active_uid);
            my ($unick, $ident, $host);
            my ($unique_data_id, $sth);
            my @result;

            if ($temp =~ /(.*?):(.*?):(.*)/) {
                ($unick, $ident, $host) = ($1, $2, $3);
            }

            $unique_data_id = get_unique_id($unick, $ident, $host, $channel);
            $sth = $dbh->prepare('SELECT `unique_id`,`unique_data_id` FROM track_data WHERE unique_data_id = ?');
            $sth->execute($unique_data_id);

            @result = $sth->fetchrow_array();

            if (!$result[0]) {
                $sth = $dbh->prepare(
                    'INSERT INTO track_data (server, channel, unique_id, unique_data_id) VALUES (?, ?, ?, ?)'
                );
                $sth->execute($server_real_address, $channel, $active_uid, $unique_data_id);
            }
        }
    }
}

sub notice {
    my ($server, $message, $sender, $sender_hostname, $recipient) = @_;
    my $date_last_seen;
    my $unick = $active_nick;

    my %months = (
        Jan => '01',
        Feb => '02',
        Mar => '03',
        Apr => '04',
        May => '05',
        Jun => '06',
        Jul => '07',
        Aug => '08',
        Sep => '09',
        Oct => '10',
        Nov => '11',
        Dec => '12',
    );

    if ($message =~ /Info for \002(.*?)\002/xms) {
        $unick = $1 if $unick eq 'None';
    }

    if ($message =~
        /Time registered\W*: (\w+) (?<day>\d+)-(?<month>\w+)-(?<year>\d+) (?<hour>\d+):(?<min>\d+):(?<sec>\d+) GMT/xms
    ) {
        my $datetime =
            $+{year} . '-'
          . $months{$+{month}} . '-'
          . $+{day} . ' '
          . $+{hour} . ':'
          . $+{min} . ':'
          . $+{sec};
        my $sth = $dbh->prepare(
            "UPDATE $sql_table SET `registered` = ?, date_registered = ? WHERE `nickname` = ?"
        );
        $sth->execute(1, $datetime, $unick);
    }

    if ($message =~
        /Last seen time\W*: (\w+) (?<day>\d+)-(?<month>\w+)-(?<year>\d+) (?<hour>\d+):(?<min>\d+):(?<sec>\d+) GMT/xms
    ) {
        my $datetime =
            $+{year} . '-'
          . $months{$+{month}} . '-'
          . $+{day} . ' '
          . $+{hour} . ':'
          . $+{min} . ':'
          . $+{sec};
        my $sth = $dbh->prepare(
            "UPDATE $sql_table SET `date_last_seen` = ? WHERE `nickname` = ?");
        $sth->execute($datetime, $unick);
        $unick = "None";
    }
}

sub help {
    my $help = <<HELP;

        \%_\%C\%UHelp\%N

        \%U/track quiet\%U
            Toggle quiet. If this is on, it wont show when a person
            is added or already existing in the database.

        \%U/track <sql|raw> count\%U
            Print amount of database entries.

        \%U/track import <file>\%U
            This allows you to import AKA databases. AKA is a popular
            mIRC script which allows you to keep track of people by
            nickname and hostmask. This imports all of the nicknames
            and hosts and fills in the ident with AKAImport, since
            AKA does not keep track of idents.

        \%U/track search <sql|raw> <\%_ident\%_|\%_nick\%_|\%_host\%_|\%_all\%_> \%I(literal/regex)\%I <input>\%U
            The first parameter specifies whether or not you want to search
            the raw database, or the SQL database. You then choose which attribute
            to parse; alternatively you can search all of them (slow, depending on db size)
            For your input parameter, string literals or regular expressions can be unused.
            See below for a better idea at how these work.

        \%U\%_\%CExamples\%N
            /track search raw host .*(or|pa|tx|fl)..*comcast.*
            /track search raw host (24|195)[.-](226|185)[-.][0-9]{1,3}[-.][0-9]{1,3}
                Matches: 195.185.x.x
                Matches: CPE-x24-185-xxx-xx.y.y.y.net.au
            /track search raw nick Zi[dptb]+y
                Matches: Ziddy, Zippy, Zidy, Zitty, Zipty, etc.
        TODO: XXX: FIXME:  XXXXXXXXXXXXXXXXX ADD SQL EXAMPLES ONCE IMPLEMENTED XXXXXXXXXXXXXXXXXXXXXXX
HELP
    
    Irssi::print($help);
    return $SUCCESS;
}

sub track_banner {
    my $banner = q/
        %KIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII%N
        %KIIIIIIIIIIIIIIIIIIIIIIII%RNNNN%KII%RN%RNN%RN%KIIIIIIIIIIIIIIIIIIIIIII%N
        %KIIIIIIIIIIIIIIIIIIIIIII%RN%KIIII%RNN%KIIII%RN%KIIIIIIIIIIIIIIIIIIIIII%N
        %KIIIIIIIIIIIIIIIIIIIIIII%RN%KIIIIIIIIII%RN%KIIIIIIIIIIIIIIIIIIIIII%N
        %KIIIIIIIIIIIIIIIIIIIIIII%RN%KIIIIIIIIII%RN%KIIIIIIIIIIIIIIIIIIIIII%N
        %KIIIIIIIIIIIIIIIIIIIIIII%RN%KIIIIIIIIII%RN%KIIIIIIIIIIIIIIIIIIIIII%N
        %KIIIIIIIIIIIIIIIIIIIII%R8888888888888888%KIIIIIIIIIIIIIIIIIIII%N
        %KIIIIIIIIIIIIIIIIIIIIII%B#%RNNNN%RM%KII%RNNNN%RN%B#%KIIIIIIIIIIIIIIIIIIIII%N
        %KIIIIIIIIIIIIIIIIIIIIIII%RN%KII%YI%RM%RN%RN%RN%KII%YI%RN%KIIIIIIIIIIIIIIIIIIIIII%N
        %KIIIIIIIIIIIIIIIIIIIIIII%RNNNNM%KII%RNNNNN%KIIIIIIIIIIIIIIIIIIIIII%N
        %KIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII%N
        %KIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII%B#%KIII%N
        %KIII%B########%KIIIIIIIIIIIIIIIIIIIIII%B#%KIIIIIIIIIIIIIIIIIII%B#%KIII%N
        %KIII%B##%KII%B##%KI%B#%KII%B#%KI%B##%KIII%B####%KIII%B##%KIIII%B#%KIIIIIIIIII%B######%KIII%B#%KIII%N
        %KIIIIIII%B##%KIIII%B##%KI%B#%KI%B##%KII%B#%KIII%B#%KII%B##%KII%B#%KII%B##%KIIIIII%B%B##%N%KIII%B#%KIII%B#%KIII%N
        %KIIIIIII%B#%KIIIII%B#%KIIIIII%B###%KII%B##%KIIIIII%B####%N%KIIIIIII%B%B##%N%KIII%B##%KII%B#%KIII%N
        %KIIIIIII%B#%KIIIII%B#%KIIII%B#%KIII%B#%KII%B##%KIIIIII%B#%KII%B##%KIIIIII%B##%KIII%B#%KIII%B#%KIII%N
        %KIIIII%B#####%KII%B###%B#%KII%B######%KII%B#####%KI%B##%KII%B###%KII%G#%KII%B%B######%KI%B####%KII%N
        %KIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII%B##%KIIIIIIIIIII%N
        %KIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII%B####%KIIIIIIIIII%N
        %KIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII%N/;

    Irssi::print($banner);

    return $SUCCESS;
}