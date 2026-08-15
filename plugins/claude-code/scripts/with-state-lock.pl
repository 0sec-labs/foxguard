#!/usr/bin/env perl
use strict;
use warnings;
use Errno qw(EAGAIN EWOULDBLOCK EEXIST);
use Fcntl qw(:DEFAULT :flock F_SETFD S_IFMT S_IFREG);

sub is_safe_lock {
    my ($lock) = @_;
    my @stat = stat($lock);

    return @stat
        && (($stat[2] & S_IFMT) == S_IFREG)
        && $stat[3] == 1
        && (($stat[2] & 0777) == 0600);
}

my ($lock_path, @command) = @ARGV;
exit 1 unless defined($lock_path) && @command;
my $no_follow = eval { Fcntl::O_NOFOLLOW() };
exit 1 if $@ || !defined($no_follow);

my $old_umask = umask 0077;
my $created = sysopen(my $lock, $lock_path, O_CREAT | O_EXCL | O_RDWR | $no_follow, 0600);
my $create_errno = $! unless $created;
umask $old_umask;
if (!$created) {
    exit 1 unless $create_errno == EEXIST;
    sysopen($lock, $lock_path, O_RDWR | $no_follow) or exit 1;
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

# Preserve the kernel-held lock through exec; it releases when the action exits.
defined fcntl($lock, F_SETFD, 0) or exit 1;
exec @command;
exit 127;
