#!/usr/bin/env perl
use strict;
use warnings;
use Errno qw(EAGAIN EWOULDBLOCK EEXIST);
use Fcntl qw(:DEFAULT :flock F_SETFD S_IFMT S_IFREG S_IFDIR);

my $no_follow = eval { Fcntl::O_NOFOLLOW() };
exit 1 if $@ || !defined($no_follow);
my $directory_only = eval { Fcntl::O_DIRECTORY() };
exit 1 if $@ || !defined($directory_only);

sub valid_basename {
    my ($name) = @_;

    return defined($name)
        && length($name) > 0
        && length($name) <= 255
        && $name !~ m{/}
        && $name !~ /\A\.{1,2}\z/
        && $name =~ /\A[A-Za-z0-9._-]+\z/;
}

sub is_safe_directory {
    my ($directory) = @_;
    my @stat = stat($directory);

    return @stat && (($stat[2] & S_IFMT) == S_IFDIR);
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
    my ($path) = @_;
    my $components = absolute_components($path);
    return unless $components;
    my $flags = O_RDONLY | O_NONBLOCK | $directory_only | $no_follow;
    my $current;

    sysopen($current, q(/), $flags) or return;
    return unless is_safe_directory($current);
    for my $component (@{$components}) {
        chdir($current) or return; # chdir FILEHANDLE uses fchdir.
        my $next;
        sysopen($next, $component, $flags) or return;
        return unless is_safe_directory($next);
        $current = $next;
    }
    chdir($current) or return;
    return $current;
}

sub is_safe_lock {
    my ($lock) = @_;
    my @stat = stat($lock);

    return @stat
        && (($stat[2] & S_IFMT) == S_IFREG)
        && $stat[3] == 1
        && (($stat[2] & 0777) == 0600);
}

my ($root, $lock_name, @command) = @ARGV;
exit 1 unless defined($root)
    && valid_basename($lock_name)
    && @command;
my $directory = open_absolute_directory($root);
exit 1 unless $directory;
chmod 0700, q(.) or exit 1;

my $old_umask = umask 0077;
my $created = sysopen(my $lock, $lock_name, O_CREAT | O_EXCL | O_RDWR | $no_follow, 0600);
my $create_errno = $! unless $created;
umask $old_umask;
if (!$created) {
    exit 1 unless $create_errno == EEXIST;
    sysopen($lock, $lock_name, O_RDWR | $no_follow) or exit 1;
}
exit 1 unless is_safe_lock($lock);
my $locked = 0;
for (1 .. 40) {
    if (flock($lock, LOCK_EX | LOCK_NB)) {
        $locked = 1;
        last;
    }
    exit 1 unless $! == EAGAIN || $! == EWOULDBLOCK;
    select undef, undef, undef, 0.05;
}
exit 1 unless $locked;
exit 1 unless is_safe_lock($lock);

close($directory) or exit 1;
chdir(q(/)) or exit 1;
defined fcntl($lock, F_SETFD, 0) or exit 1;
exec @command;
exit 127;
