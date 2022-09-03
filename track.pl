#!/usr/bin/env perl

use strict;
use warnings;
use diagnostics;

use feature qw/state/;

use Irssi qw(servers
  settings_get_str  settings_add_str
  settings_get_bool settings_add_bool
  settings_set_str settings_set_bool);
use MIME::Base64 qw(encode_base64 decode_base64);
use Data::Dumper;
use DateTime;

#use Term::CLI::Command::Help;
use DBI;

use vars qw($VERSION %IRSSI);

our $VERSION = "3.0";

%IRSSI = (
    authors     => "Ziddy",
    contact     => "DALnet",
    name        => "track",
    description => "Keeps track of users by building a database"
      . "of online, joining and nickchanges. Regex-cabable"
      . "for the most part, AKA import available. Search by"
      . "ident, nick or host",
    license => "Public Domain",
    url     => "none",
);

my $quiet_mode        = 0;
my $name_buffer_count = 0;
my $sql               = 0;
my $pulling_whois     = 0;
my $track_file;
my $track_fh;
my $active_server;
my $active_nick;
my $active_uid;
my ($sql_host, $sql_pass, $sql_user, $sql_table, $sql_port, $sql_db);
my $dbh;

sub init {
    my $connect_msg;
    my $db_count = 0;

    settings_add_bool('track', 'track_quiet',      0);
    settings_add_bool('track', 'track_sql_enable', 0);
    settings_add_bool('track', 'track_raw_enable', 0);
    settings_add_str('track', 'track_sql_host',  '');
    settings_add_str('track', 'track_sql_user',  '');
    settings_add_str('track', 'track_sql_pass',  '');
    settings_add_str('track', 'track_sql_port',  '');
    settings_add_str('track', 'track_sql_table', '');
    settings_add_str('track', 'track_sql_db',    '');
    settings_add_str('track', 'track_file',
        Irssi::get_irssi_dir() . '/track.lst');


    $track_file = settings_get_str('track_file');

    if ($track_file && -e $track_file) {
        $connect_msg =
            "%NLoaded track database: '%G$track_file%N' "
          . "(Size: %C"
          . (stat $track_file)[7];
        $connect_msg .= "%N)";
    } else {
        $track_file = Irssi::get_irssi_dir() . '/track.lst';
        Irssi::print("Initializing track database (raw) using default");
        Irssi::print("location: " . $track_file);
    }

    $quiet_mode = settings_get_bool('track_quiet');

    if ($quiet_mode) {
        $connect_msg .= "(Quiet: %GON%N)";
    } else {
        $connect_msg .= "(Quiet: %ROFF%N)";
    }

    $sql_host  = settings_get_str('track_sql_host');
    $sql_user  = settings_get_str('track_sql_user');
    $sql_pass  = settings_get_str('track_sql_pass');
    $sql_port  = settings_get_str('track_sql_port');
    $sql_table = settings_get_str('track_sql_table');
    $sql_db    = settings_get_str('track_sql_db');

    if (settings_get_str('track_sql_enable')) {
        if (check_sql_info()) {
            sql_init();
            my $sth   = $dbh->prepare("SELECT COUNT(*) FROM $sql_table;");
            $sth->execute;
            $db_count = $sth->fetchrow();
        }
    } else {
        Irssi::print("%RSQL mode not active");
    }

    open $track_fh, '+<', $track_file
      or die "Could not open '$track_file' for read-write operations: $@\n";

    my @t  = <$track_fh>;
    my $lc = scalar @t;

    Irssi::print($connect_msg . "\n");
    Irssi::print("Raw DB: %G$lc");
    Irssi::print("SQL DB: %G$db_count");
}

my $help =
    "\n%_%C%UHelp%N\n\n"
  . "%U/track gather%U\n"
  . "     Join your channels then run this\n"
  . "     to gather nicks already online\n"
  . "     This may take a while on first run\n\n"
  .

  "%U/track quiet%U\n"
  . "     Toggle quiet. If this is on, it wont\n"
  . "     show when a person is added or already\n"
  . "     existing in the database\n\n"
  .

  "%U/track count%U\n" . "     Print amount of database entries\n\n" .

  "%U/track import <file>%U\n"
  . "     This allows you to import AKA data-\n"
  . "     bases. AKA is a popular mIRC script\n"
  . "     which allows you to keep track of people\n"
  . "     by nickname and hostmask. This imports\n"
  . "     all of the nicknames and hosts and fills\n"
  . "     in the ident with AKAImport, since AKA does\n"
  . "     not keep track of idents\n\n"
  .

  "%U/track search <sql|raw> <%_ident%_|%_nick%_|%_host%_|%_all%_> %I(literal/regex)%I <input>%U\n"
  . "     The first parameter specifies whether or not you want to search\n"
  . "     the raw database, or the SQL database. You then choose which attribute\n"
  . "     to parse; alternatively you can search all of them (slow, depending on db size)\n"
  . "     For your input parameter, string literals or regular expressions\n"
  . "     can be unused.\n"
  . "     See below for a better idea at how these work.\n\n"
  .

  "%U%_%CExamples%N\n"
  . "     /track search raw host .*(or|pa|tx|fl)..*comcast.*\n"
  . "     /track search raw host (24|195)[.-](226|185)[-.][0-9]{1,3}[-.][0-9]{1,3}\n"
  . "         Matches: 195.185.x.x\n"
  . "         Matches: CPE-x24-185-xxx-xx.y.y.y.net.au\n"
  . "     /track search raw nick Zi[dptb]+y\n"
  . "         Matches: Ziddy, Zippy, Zidy, Zitty, Zipty, etc.\n"
  . "TODO: XXXXXXXXXXXXXXXXX ADD SQL EXAMPLES ONCE IMPLEMENTED XXXXXXXXXXXXXXXXXXXXXXX\n\n";

sub whois_signal {
    my ($server, $data, $txtserver) = @_;
    my ($me, $nick, $ident, $host, $unused, $real_name) = split(" ", $data);
    my @list       = <$track_fh>;
    my $registered = 0;
    my $unique_id  = get_unique_id($nick, $ident, $host);
    my $chans;
    $active_server = $server;
    $active_uid    = $unique_id;
    $nick = conv($nick);
    $ident =~ s/^~//;
    $ident = conv($ident);

    $real_name =~ s/^://;
    $real_name =~ s/[^ -~]//g;

    Irssi::print("derder: $data");

    # 307 - identified for nick
    # 319 - channels list

    # 2 noisy fr
    # Irssi::active_server->send_raw("PRIVMSG $nick :\001VERSION\001");
    if ($data =~ /has identified for this nick/) {
        $registered = 1;
    }

    if ($data =~ /channels/) {
        my ($unused, $channels) = split($data, ':');
        my $sth =
          $dbh->prepare("SELECT `channels` FROM $sql_table WHERE unique_id = ?")
          or die("Unable to prepare statement: " . $dbh->errstr);
        $sth->execute($unique_id);

        my @result = $sth->fetchrow_array();
        if (!$result[0] or $result[0] =~ /None/) {
            $sth = $dbh->prepare(
                "UPDATE $sql_table SET channels = ? WHERE unique_id = ?");
            $sth->execute($channels, $unique_id);
        } else {
        }
    }

    mickles_pickles($server, $nick, $ident, $host, $real_name, $chans,
        $registered);
}

sub joining {
    my ($server, $channame, $unick, $host) = @_;
    $unick = conv($unick);
    my @spl   = split(/@/, $host);
    my $ident = $spl[0];
    my $mask  = $spl[1];
    ($ident = $ident) =~ s/^~//;
    $ident         = conv($ident);
    $active_server = $server;
    $active_nick   = $unick;

    Irssi::active_server->send_raw("WHOIS $unick");
    Irssi::active_server->send_raw("nickserv info $unick");
}

sub nchange {
    my ($server, $newnick, $oldnick, $host) = @_;
    $newnick = conv($newnick);
    my @spl   = split(/@/, $host);
    my $ident = $spl[0];
    my $mask  = $spl[1];
    ($ident = $ident) =~ s/^~//;
    $ident         = conv($ident);
    $active_server = $server;
    $active_nick   = $newnick;

    Irssi::active_server->send_raw("WHOIS $newnick");
    Irssi::active_server->send_raw("nickserv info $newnick");
}

sub mickles_pickles {
    my ($server, $nick, $ident, $mask, $real_name, $channels, $registered) = @_;
    my $name_buffer_max = 25;
    $channels   //= "None";
    $registered //= 0;

    if (settings_get_str('track_raw_enable')) {
        open(my $fh2, '<', $track_file);
        my @list = <$fh2>;
        close($fh2);
        open(my $fh, '>>', $track_file);
        $name_buffer_count++;

        if (!grep(/$nick;$ident;$mask/, @list)) {
            print $fh "$nick;$ident;$mask\n";
            Irssi::print("%GADDED $nick;$ident;$mask") if !$quiet_mode;
        } else {
            Irssi::print("%REXIST $nick;$ident;$mask") if !$quiet_mode;
        }

        close($fh);

        if ($name_buffer_count >= $name_buffer_max) {
            open(my $fhr, '<', $track_file);
            my @list = <$fhr>;
            close($fhr);
            my @name_buffer = uniq(@list);
            open(my $fhw, '>', $track_file);
            print $fhw @name_buffer;
            close($fhw);
            $name_buffer_count = 0;
        }
    }

    if (settings_get_bool('track_sql_enable')) {
        my $unique_id = get_unique_id($nick, $ident, $mask);
        my $exists;
        
        my $sth = $dbh->prepare(
            "SELECT `unique_id` FROM $sql_table WHERE unique_id = ?")
          or die("Unable to prepare statement: " . $dbh->errstr);
        $sth->execute($unique_id);

        my @result = $sth->fetchrow_array();
        if (!$result[0]) {
            $sth = $dbh->prepare(
                qq/
                INSERT INTO `$sql_table` (
                nickname,           ident,  hostname,
                date_first_seen,  date_last_seen, real_name,
                registered,             bot, unique_id
                ) VALUES (?,?,?,?,?,?,?,?,?)/
            ) or warn "Can't prepare statement: $! ($@) $dbh->errstr;";

            $sth->execute(
                $nick,          $ident,
                $mask,          get_sql_time(),
                get_sql_time(), $real_name,
                $registered,    0,
                $unique_id
            ) or warn "Sry m8 no go: $! ($@) $dbh->errstr";
        } else {
            $sth = $dbh->prepare(
                "UPDATE `$sql_table` SET date_last_seen = ?, real_name = ?  WHERE unique_id = ?"
            );
            $sth->execute(get_sql_time(), $real_name, $unique_id);

            #TODO: Quieter way to collect channels
        }
    }
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
    chomp($input);
    my @spl = split(/\s/, $input);
    my $type;

    if (defined $spl[0]) {
        $type = $spl[0];
    } else {
        Irssi::print($help);
        return;
    }

    if ($type eq "set") {
        track_options($input);
        return;
    }

    if ($type eq "gather") {
        namechan();
    }

    if ($type eq "import_raw") {
        raw_to_sql();
    }

    if ($type eq "debug") {
        Irssi::print("Here too: " . Irssi::active_server->{real_address});
    }

    if ($type eq "count") {
        my $which = $spl[1];
        $which //= "raw";
        if ($which eq "raw") {
            open my $fh, '<', settings_get_str("track_file");
            my @tmp = <$fh>;
            close $fh;
            Irssi::print("%GRaw Database Entries%N: " . scalar(@tmp));
        } elsif ($which eq "sql") {
            my $sth = $dbh->prepare("SELECT COUNT(*) FROM $sql_table");
            $sth->execute();
            my $dbcount = $sth->fetchrow();
            Irssi::print("%GSQL Database Entries%N: $dbcount");
        }
       return; 
    } elsif ($type eq "quiet") {
        $quiet_mode = $quiet_mode ? 0 : 1;
        Irssi::print("%GQuiet mode set to $quiet_mode");
        settings_set_bool("track_quiet", $quiet_mode);
        return;
    } elsif ($type eq "help") {
        Irssi::print($help);
        return;
    } elsif ($type eq "search") {
        my ($hehe, $which, $field, $term) = split / /, $input;
        my $pcr = qr/$term/;

        if ($which eq "raw") {
            open my $stupid_fh, '<', $track_file;
            my @dongs = <$stupid_fh>;
            close $stupid_fh;

            foreach my $line (@dongs) {
                chomp($line);
                my ($line_nick, $line_ident, $line_host) = split /;/, $line;

                if ($field eq "host") {
                    if ($line_host =~ /$pcr/) {
                        Irssi::print(
                            "%GHost[%n$term%G]%n: $line_nick used $line_ident on -> %_$line_host%_ <-"
                        );
                        $match = 1;
                    }
                } elsif ($field eq "nick") {
                    if ($line_nick =~ /$pcr/) {
                        Irssi::print(
                            "%GNick[%n$term%G]%n: -> %_$line_nick%_ <- used $line_ident on $line_host"
                        );
                        $match = 1;
                    }
                } elsif ($field eq "ident") {
                    if ($line_ident =~ /$pcr/) {
                        Irssi::print(
                            "%GIdent[%n$term%G]%n: $line_nick used -> %_$line_ident%_ <- on $line_host"
                        );
                        $match = 1;
                    }
                } elsif ($field eq "all") {
                    if ($line =~ /$pcr/) {
                        Irssi::print(
                            "%GALL[%n$term%G]%N: -> $line_nick used $line_ident on $line_host"
                        );
                        $match = 1;
                    }
                } else {
                    Irssi::print("%RUnknown search field%N");
                    last;
                }
            }
        }
    }

    if (!$match) {
        Irssi::print("%RNo data to return");
    }
}

sub uniq {
    my %seen;
    grep !$seen{$_}++, @_;
}

sub namechan {
    my $count = 0;
    
    foreach my $serv (Irssi::channels()) {
        my $curserv = $serv->{server}->{tag};
        my $sth = $dbh->prepare(
            "UPDATE `$sql_table` SET date_last_seen = ?, real_name = ?, servers = ? WHERE unique_id = ?"
        );
        foreach my $nname ($serv->nicks()) {
            my $unick = conv($nname->{nick});
            open(my $fh, '<', $track_file);
            my @list = <$fh>;
            close($fh);
            my $real_name = $nname->{realname};
            my @temp      = split("@", $nname->{host});
            my $ident     = $temp[0];
            my $host      = $temp[1];
            my $unique_id = get_unique_id($unick, $ident, $host);
            my $servers   = Irssi::active_server->{real_address};
            $ident     =~ s/^~//;
            $real_name =~ s/[^ -~]//g;    # clear all non-printable characters

            if (!grep(/$unick;$ident;$host/, @list)) {
                Irssi::active_server->send_raw("WHOIS " . $unick);
                $count++;
            } else {
                if (settings_get_bool('track_sql_enable')) {
                    $sth->execute(get_sql_time(), $real_name, $servers,
                        $unique_id);
                }
                Irssi::print("%RAlready gathered $unick") if !$quiet_mode;
            }
        }
    }
    Irssi::print("%GGathering complete - Added $count new entries");
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

#Messy for now
sub importAKA {
    my $input = $_[0];
    if (-e $input) {
        open(my $fh, '<', $input);
        my @list = <$fh>;
        close($fh);
        my $ip = 0;
        my ($string, $import);
        foreach my $line (@list) {
            chomp($line);
            my @nicks;
            if ($line =~ /(.*?)@(.*+)/g) {
                $ip = $2;
            } elsif ($line =~ /(.*)~/g) {
                my @nicksplit = split(/~/, $1);
                foreach my $ns (@nicksplit) {
                    push(@nicks, $ns);
                }
            }
            foreach my $nick (@nicks) {
                my $snick = conv($nick);
                if ($snick and $ip) {
                    if (length($snick) > 1 and length($ip) > 1) {
                        $string .= "$snick;AKAImport;$ip;;;";
                    }
                }
            }
        }
        my @arrn = split(/;;;/, $string);
        open(my $fh2, '>>', $track_file);
        foreach my $out (@arrn) {
            if (length($out) > 1) {
                $out =~ s/\r//g;
                print $fh2 "$out\n";
                $import++;
            }
        }
        close($fh2);
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

    chomp(my $t_out =
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

        chomp($t_out = `mysql -e '$create_database' 2>&1`);
        $t_out = "%GGood%N" if length $t_out < 3;
        Irssi::print("%YDatabase creation result: $t_out");

        chomp($t_out = `mysql -e 'use "$sql_db"; $create_main_table' 2>&1`);
        $t_out = "%GGood%N" if length $t_out < 3;
        Irssi::print("%YTable creation result: $t_out");

        chomp(
            $t_out = `mysql -e 'use "$sql_db";
            GRANT ALL PRIVILEGES ON $sql_table.* TO "$sql_user"@"$sql_host" IDENTIFIED BY "$sql_pass";
            GRANT ALL PRIVILEGES ON track_data.* TO "$sql_user"@"$sql_host" IDENTIFIED BY "$sql_pass";
            FLUSH PRIVILEGES;' 2>&1`
        );
        $t_out = "%GGood%N" if length $t_out < 3;
        Irssi::print("%YPrivilege creation result: $t_out");
    }

    $dbh = DBI->connect("DBI:MariaDB:$sql_db", $sql_user, $sql_pass)
      or die "Unable to connect to SQL database: $!\n";
    Irssi::print("%GSuccessfully connected to database %C$sql_db%N");
    Irssi::print("%G*%R*%Y*%B*%N SQL Mode fully activated!!! %B*%Y*%R*%G*%N");
    settings_set_bool("track_sql_enable", 1);
}

sub track_options {
    my $input = $_[0];
    $input =~ s/set //;

    my @commands = split / /, $input;

    if ($commands[0] eq 'sql' && !defined($commands[1])) {
        if (check_sql_info()) {
            $sql = 1;
            Irssi::print("%GSQL mode successfully activated");
            sql_init();
        } else {
            my @missing;
            foreach my $opt ("host", "db", "table", "user", "pass", "port") {
                if (!settings_get_str("track_sql_$opt")) {
                    push(@missing, $opt);
                }
            }
            Irssi::print(
                "%RSQL mode cannot be enabled until required information has been supplied via 'set sql'"
            );
            Irssi::print("%RMissing SQL information: " . join ', ', @missing);
        }
    } elsif ($commands[0] eq 'sql'
        && $commands[1] =~ /(host|db|user|pass|port|table)/) {
        my $value = $commands[2];
        if (settings_get_str("track_sql_$1")) {
            settings_set_str("track_sql_$1", $value);
            Irssi::print("Overwrote current $1 value");
        } else {
            settings_set_str("track_sql_$1", $value);
            Irssi::print("Added $1");
        }
        Irssi::print("%GSQL setting '$1' has been set to '$value'");
    } elsif ($commands[0] eq 'raw') {

    } else {
        Irssi::print("%RUnknown directive passed to 'set'");
    }
}

sub check_sql_info {
    ($sql_host, $sql_user, $sql_pass, $sql_port, $sql_table, $sql_db) = (
        settings_get_str("track_sql_host"),
        settings_get_str("track_sql_user"),
        settings_get_str("track_sql_pass"),
        settings_get_str("track_sql_port"),
        settings_get_str("track_sql_table"),
        settings_get_str("track_sql_db")
    );

    my $passed = 0;
    Irssi::print("Checking for required SQL information");

    if (   length $sql_host > 1
        && length $sql_user > 1
        && length $sql_pass > 1
        && length $sql_port > 1
        && length $sql_table > 1
        && length $sql_db > 1) {
        $passed = 1;
        Irssi::print("%GAll required SQL settings found");
    }

    return $passed;
}

sub get_sql_time {
    my $dt = DateTime->from_epoch(epoch => time());
    return $dt->strftime('%Y-%m-%d %H:%M:%S');
}

sub raw_to_sql {
    open my $fh, '<', settings_get_str('track_file');
    my @list = <$fh>;
    close $fh;

    my $sth = $dbh->prepare(
        "INSERT INTO $sql_table (nickname, ident, hostname, date_first_seen, date_last_seen, real_name, registered, channels, servers, bot, unique_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    ) or warn "Can't prepare statement: $! ($dbh->errstr)";

    foreach my $entry (@list) {
        my ($unick, $ident, $host) = split(';', $entry);
        my ($date_first_seen, $date_last_seen) =
          (get_sql_time(), get_sql_time());
        my ($registered, $bot) = (0, 0);
        my $real_name = "IMPORTED";
        my $channels  = "";
        my $servers   = "";
        my $unique_id = get_unique_id($unick, $ident, $host);

        $sth->execute(
            $unick,           $ident,          $host,
            $date_first_seen, $date_last_seen, $real_name,
            $registered,      $channels,       $servers,
            $bot,             $unique_id
        ) or warn "Can't execute prepared statement: $! ($dbh->errstr)";
    }
}

sub process_chans {
    my ($server, $chans, $server_real_address) = @_;

    if ($chans =~ /.*? .*? :#/) {
        my @spl = split(/:/, $chans);
        my $chanlist = $spl[1];
        my @chansplit = split(" ", $chanlist);

        foreach my $channel (@chansplit) {
            my $temp = decode_base64($active_uid);
            my ($unick, $ident, $host);
            if ($temp =~ /(.*?):(.*?):(.*)/) {
                $unick = $1;
                $ident = $2;
                $host  = $3;
            }
            my $unique_data_id = get_unique_id($unick, $ident, $host, $channel);
            my $sth = $dbh->prepare("SELECT `unique_id`,`unique_data_id` FROM track_data WHERE unique_data_id = ?")
                or die("Unable to prepare statement: " . $dbh->errstr);
            $sth->execute($unique_data_id);

            my @result = $sth->fetchrow_array();
            if (!$result[0]) {
                $sth = $dbh->prepare("INSERT INTO track_data (server, channel, unique_id, unique_data_id) VALUES (?, ?, ?, ?)");
                $sth->execute($server_real_address, $channel, $active_uid, $unique_data_id);
            }
        }
    }
}

sub notice {
    my ($server, $message, $sender, $sender_hostname, $recipient) = @_;
    my $time_registered;
    my $date_last_seen;
    my $unick = $active_nick;

    my %months = (
        Jan => "01",
        Feb => "02",
        Mar => "03",
        Apr => "04",
        May => "05",
        Jun => "06",
        Jul => "07",
        Aug => "08",
        Sep => "09",
        Oct => "10",
        Nov => "11",
        Dec => "12",
    );

    if ($message =~ /Info for \002(.*?)\002/) {
        $unick = $1 if $unick eq "None";
    }

    if ($message =~
        /Time registered\W*: (\w+) (?<day>\d+)-(?<month>\w+)-(?<year>\d+) (?<hour>\d+):(?<min>\d+):(?<sec>\d+) GMT/
    ) {
        my $datetime =
            $+{year} . "-"
          . $months{$+{month}} . "-"
          . $+{day} . " "
          . $+{hour} . ":"
          . $+{min} . ":"
          . $+{sec};
        my $sth = $dbh->prepare(
            "UPDATE $sql_table SET `registered` = ?, date_registered = ? WHERE `nickname` = ?"
        );
        $sth->execute(1, $datetime, $unick);
    }

    if ($message =~
        /Last seen time\W*: (\w+) (?<day>\d+)-(?<month>\w+)-(?<year>\d+) (?<hour>\d+):(?<min>\d+):(?<sec>\d+) GMT/
    ) {
        my $datetime =
            $+{year} . "-"
          . $months{$+{month}} . "-"
          . $+{day} . " "
          . $+{hour} . ":"
          . $+{min} . ":"
          . $+{sec};
        my $sth = $dbh->prepare(
            "UPDATE $sql_table SET `date_last_seen` = ? WHERE `nickname` = ?");
        $sth->execute($datetime, $unick);
        $unick = "None";
    }
}
my $lmao = q/
%KIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII%N
%KIIIIIIIIIIIIIIIIIIIIIIII%RNNNN%KIII%RNN%RN%KIIIIIIIIIIIIIIIIIIIIIII%N
%KIIIIIIIIIIIIIIIIIIIIIII%RN%KIIIIIIIIII%RN%KIIIIIIIIIIIIIIIIIIIIII%N
%KIIIIIIIIIIIIIIIIIIIIIII%RN%KIIIIIIIIII%RN%KIIIIIIIIIIIIIIIIIIIIII%N
%KIIIIIIIIIIIIIIIIIIIIIII%RN%KIIIIIIIIII%RN%KIIIIIIIIIIIIIIIIIIIIII%N
%KIIIIIIIIIIIIIIIIIIIIIII%RN%KIIIIIIIIII%RN%KIIIIIIIIIIIIIIIIIIIIII%N
%KIIIIIIIIIIIIIIIIIIIII%R8888888888888888B%KIIIIIIIIIIIIIIIIIII%N
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

Irssi::print("$lmao");
Irssi::command_bind('track' => \&track);

Irssi::signal_add('message join',       'joining');
Irssi::signal_add('message nick',       'nchange');
Irssi::signal_add('message irc notice', 'notice');

Irssi::signal_add_first('event 311', 'whois_signal');
Irssi::signal_add_last('event 319', 'process_chans');
Irssi::signal_add_last('setup changed', 'init');
init();
