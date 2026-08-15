#!/usr/bin/env perl
use strict;
use warnings;
use Errno qw(EAGAIN EWOULDBLOCK EEXIST);
use Fcntl qw(:DEFAULT :flock F_SETFD S_IFMT S_IFREG S_IFDIR);

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
    && $root =~ m{\A/}
    && index($root, "\0") == -1
    && valid_basename($lock_name)
    && @command;
my $no_follow = eval { Fcntl::O_NOFOLLOW() };
exit 1 if $@ || !defined($no_follow);
my $directory_only = eval { Fcntl::O_DIRECTORY() };
exit 1 if $@ || !defined($directory_only);
sysopen(my $directory, $root, O_RDONLY | O_NONBLOCK | $directory_only | $no_follow)
    or exit 1;
exit 1 unless is_safe_directory($directory);
chdir($directory) or exit 1;
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

# Preserve the rooted directory and kernel-held lock through exec.
defined fcntl($directory, F_SETFD, 0) or exit 1;
defined fcntl($lock, F_SETFD, 0) or exit 1;
$ENV{FG_STATE_LOCK_DIR_FD} = fileno($directory);
exec @command;
exit 127;
