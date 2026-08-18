#!/usr/bin/env perl
use strict;
use warnings;
use Errno qw(ENOENT EEXIST);
use Fcntl qw(:DEFAULT S_IFMT S_IFREG S_IFDIR);
use File::Temp qw(tempfile);

my $no_follow = eval { Fcntl::O_NOFOLLOW() };
exit 1 if $@ || !defined($no_follow);
my $directory_only = eval { Fcntl::O_DIRECTORY() };
exit 1 if $@ || !defined($directory_only);
my ($temp_name, $temp_dev, $temp_ino);

sub valid_basename {
    my ($name) = @_;

    return defined($name)
        && length($name) > 0
        && length($name) <= 255
        && $name !~ m{/}
        && $name !~ /\A\.{1,2}\z/
        && $name =~ /\A[A-Za-z0-9._-]+\z/;
}


sub valid_limit {
    my ($limit) = @_;

    return defined($limit)
        && $limit =~ /\A[0-9]{1,6}\z/
        && $limit <= 131072;
}

sub is_directory {
    my ($file) = @_;
    my @stat = stat($file);

    return @stat && (($stat[2] & S_IFMT) == S_IFDIR);
}

sub is_regular_unlinked {
    my (@stat) = @_;

    return @stat
        && (($stat[2] & S_IFMT) == S_IFREG)
        && $stat[3] == 1;
}

sub absolute_components {
    my ($path) = @_;

    return unless defined($path)
        && $path =~ m{\A/}
        && index($path, "\0") == -1;
    return [] if $path eq q(/);
    return if $path =~ m{/\z} || $path =~ m{//};
    my @components = split m{/}, substr($path, 1), -1;
    return unless @components;
    for my $component (@components) {
        return if !length($component)
            || $component eq q(.)
            || $component eq q(..);
    }
    return \@components;
}

sub open_absolute_directory {
    my ($path, $create) = @_;
    my $components = absolute_components($path);
    return unless $components;
    my $flags = O_RDONLY | O_NONBLOCK | $directory_only | $no_follow;
    my $current;

    sysopen($current, q(/), $flags) or return;
    return unless is_directory($current);
    for my $component (@{$components}) {
        chdir($current) or return; # chdir FILEHANDLE uses fchdir.
        my $next;
        if (!sysopen($next, $component, $flags)) {
            my $open_error = $!;
            return unless $create && $open_error == ENOENT;
            my $old_umask = umask 0077;
            my $made = mkdir($component, 0700);
            my $mkdir_error = $!;
            umask $old_umask;
            return unless $made || $mkdir_error == EEXIST;
            sysopen($next, $component, $flags) or return;
        }
        return unless is_directory($next);
        $current = $next;
    }
    chdir($current) or return;
    return $current;
}

sub duplicate_locked_directory {
    my $fd = $ENV{FG_STATE_LOCK_DIR_FD};
    my $directory;

    return unless defined($fd) && $fd =~ /\A(?:0|[1-9][0-9]*)\z/;
    open($directory, q(<&), $fd) or return;
    return $directory;
}

sub matches_locked_directory {
    my ($directory, $locked_directory) = @_;
    my @directory_stat = stat($directory);
    my @locked_stat = stat($locked_directory);

    return @directory_stat && @locked_stat
        && (($directory_stat[2] & S_IFMT) == S_IFDIR)
        && (($locked_stat[2] & S_IFMT) == S_IFDIR)
        && $directory_stat[0] == $locked_stat[0]
        && $directory_stat[1] == $locked_stat[1];
}


sub open_root {
    my ($kind, $value, $create) = @_;

    exit 1 unless $kind eq q(--root);
    my $directory = open_absolute_directory($value, $create);
    exit 1 unless $directory;
    if ($create) {
        chmod 0700, q(.) or exit 1;
        return $directory;
    }
    my $locked_directory = duplicate_locked_directory();
    exit 1 unless $locked_directory && matches_locked_directory($directory, $locked_directory);
    chdir($locked_directory) or exit 1;
    return $locked_directory;
}

sub open_safe_entry {
    my ($name) = @_;
    my $file;

    return (undef, 1) unless valid_basename($name);
    if (!sysopen($file, $name, O_RDONLY | O_NONBLOCK | $no_follow)) {
        my $error = $!;
        return (undef, $error == ENOENT ? 3 : 1);
    }
    my @stat = stat($file);
    return (undef, 1) unless is_regular_unlinked(@stat);
    return ($file, 0);
}

sub target_is_safe_or_missing {
    my ($name) = @_;
    my @stat = lstat($name);

    return 1 if !@stat && $! == ENOENT;
    return is_regular_unlinked(@stat);
}

sub touch_file {
    my ($file) = @_;
    my @stat = stat($file);

    return is_regular_unlinked(@stat) && utime undef, undef, $file;
}

sub remove_entry {
    my ($name) = @_;
    my ($file, $status) = open_safe_entry($name);

    return 0 unless $file;
    my @stat = stat($file);
    my @path_stat = lstat($name);
    return 0 unless is_regular_unlinked(@stat)
        && is_regular_unlinked(@path_stat)
        && $path_stat[0] == $stat[0]
        && $path_stat[1] == $stat[1];
    return unlink($name);
}

sub read_file {
    my ($file, $limit) = @_;
    my $size = 0;
    my $buffer;

    binmode STDOUT;
    while (1) {
        my $count = sysread($file, $buffer, 8192);
        return 0 unless defined($count);
        last if $count == 0;
        $size += $count;
        return 0 if $size > $limit;
        print STDOUT $buffer or return 0;
    }
    return 1;
}

sub cleanup_temp {
    return unless defined($temp_name);
    my ($name, $dev, $ino) = ($temp_name, $temp_dev, $temp_ino);
    $temp_name = undef;
    $temp_dev = undef;
    $temp_ino = undef;

    my @stat = lstat($name);
    unlink($name) if is_regular_unlinked(@stat)
        && $stat[0] == $dev
        && $stat[1] == $ino;
}

END {
    cleanup_temp();
}


sub write_entry {
    my ($name, $limit) = @_;

    return 1 unless valid_basename($name) && valid_limit($limit) && target_is_safe_or_missing($name);
    my $old_umask = umask 0077;
    my ($temp, $path) = tempfile(q(.state.XXXXXX), DIR => q(.), UNLINK => 0);
    umask $old_umask;
    return 1 unless $temp;
    $path =~ s{\A.*/}{};
    return 1 unless valid_basename($path);

    my @stat = stat($temp);
    return 1 unless is_regular_unlinked(@stat);
    ($temp_name, $temp_dev, $temp_ino) = ($path, $stat[0], $stat[1]);
    binmode $temp;
    $SIG{HUP} = sub { exit 1; };
    $SIG{INT} = sub { exit 1; };
    $SIG{TERM} = sub { exit 1; };

    my $size = 0;
    while (1) {
        my $count = read(STDIN, my $buffer, 8192);
        unless (defined($count)) {
            cleanup_temp();
            return 1;
        }
        last if $count == 0;
        $size += $count;
        if ($size > $limit) {
            cleanup_temp();
            return 2;
        }
        unless (print {$temp} $buffer) {
            cleanup_temp();
            return 1;
        }
    }
    unless (close($temp) && target_is_safe_or_missing($name)) {
        cleanup_temp();
        return 1;
    }
    my @temp_stat = lstat($temp_name);
    unless (is_regular_unlinked(@temp_stat)
        && $temp_stat[0] == $temp_dev
        && $temp_stat[1] == $temp_ino
        && rename($temp_name, $name)) {
        cleanup_temp();
        return 1;
    }
    $temp_name = undef;
    $temp_dev = undef;
    $temp_ino = undef;
    return 0;
}

my ($anchor, $anchor_value, $action, @args) = @ARGV;
exit 1 unless defined($anchor) && defined($anchor_value) && defined($action);
exit 1 unless $action eq q(ensure-root)
    || $action eq q(touch-read) || $action eq q(remove)
    || $action eq q(write) || $action eq q(prune);
exit 1 if $action eq q(ensure-root) && @args;
my $directory = open_root($anchor, $anchor_value, $action eq q(ensure-root));

if ($action eq q(ensure-root)) {
    exit 0;
}
if ($action eq q(touch-read)) {
    exit 1 unless @args == 2 && valid_basename($args[0]) && valid_limit($args[1]);
    my ($file, $status) = open_safe_entry($args[0]);
    exit $status unless $file;
    exit 1 unless touch_file($file);
    exit(read_file($file, $args[1]) ? 0 : 1);
}

if ($action eq q(remove)) {
    exit 1 unless @args == 1 && valid_basename($args[0]);
    exit(remove_entry($args[0]) ? 0 : 1);
}

if ($action eq q(write)) {
    exit 1 unless @args == 2;
    exit write_entry(@args);
}

if ($action eq q(prune)) {
    exit 1 unless @args == 2 && valid_basename($args[0]) && $args[1] =~ /\A[a-f0-9]{64}\z/;
    my ($active, $session) = @args;
    opendir(my $entries, q(.)) or exit 1;
    my @names = sort grep { $_ ne q(.) && $_ ne q(..) } readdir($entries);
    closedir($entries) or exit 1;

    for my $name (@names) {
        next unless $name ne $active && $name =~ /-\Q$session\E\.json\z/;
        my ($file, $status) = open_safe_entry($name);
        exit 1 unless $file && touch_file($file);
    }
    for my $name (@names) {
        next unless $name !~ /-\Q$session\E\.json\z/ && $name =~ /\.json\z/;
        exit 1 unless valid_basename($name);
        my @stat = lstat($name);
        exit 1 unless is_regular_unlinked(@stat);
        next unless $stat[9] < time - 86400;
        exit 1 unless remove_entry($name);
    }
    for my $name (@names) {
        next unless $name =~ /\A\.state\./;
        exit 1 unless valid_basename($name);
        exit 1 unless target_is_safe_or_missing($name) && remove_entry($name);
    }
    exit 0;
}

exit 1;
