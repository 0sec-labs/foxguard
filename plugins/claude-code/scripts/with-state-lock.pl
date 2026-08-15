#!/usr/bin/env perl
use strict;
use warnings;
use Errno qw(EAGAIN EWOULDBLOCK);
use Fcntl qw(:DEFAULT :flock F_SETFD);

my ($lock_path, @command) = @ARGV;
exit 1 unless defined($lock_path) && @command;
my $no_follow = eval { Fcntl::O_NOFOLLOW() };
exit 1 if $@ || !defined($no_follow);

sysopen(my $lock, $lock_path, O_CREAT | O_RDWR | $no_follow, 0600) or exit 1;
exit 1 unless -f $lock;
chmod 0600, $lock or exit 1;

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

# Preserve the kernel-held lock through exec; it releases when the action exits.
defined fcntl($lock, F_SETFD, 0) or exit 1;
exec @command;
exit 127;
