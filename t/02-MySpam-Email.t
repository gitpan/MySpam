use Test::More;
use strict;
use warnings;
use Sys::Hostname;

BEGIN {
    if (!eval {require DBD::SQLite;1;}) {
        plan skip_all => "DBD::SQLite not installed: $@";
    }
    else {
        plan tests => 20;
    }
}


use_ok('MySpam::Email');

# Don't spam the testers
if( hostname ne 'lifebook' ) {
    no warnings 'redefine';
    no warnings 'once';
    *{MySpam::sendmail} = sub {1};
}


can_ok('MySpam::Email', qw/
    new
    from
    to
    cc
    subject
    list
    release
    whitelist
    unwhitelist
    list_whitelist
    subscribe
    unsubscribe
    usage
    send
/);

my $m = MySpam::Email->new('t/test.conf');

isa_ok($m, 'MySpam::Email');


ok($m->to('postmaster@localhost'), 'to');
ok($m->from('postmaster@localhost'), 'from');
ok($m->subject('MySpam::Email test'), 'subject');

$m->connect();
$m->{myspam}->_debug(1);

$m->{myspam}->quarantine_file('t/1189238618_spam');
$m->{myspam}->quarantine_file('t/1189238618_spam');
$m->{myspam}->quarantine_file('t/1189238618_spam');
ok($m->release(4), 'release');
ok(!$m->release(2023), 'not release');
ok($m->whitelist('postmaster@localhost'), 'whitelist');
ok(!$m->whitelist('invalid address'), 'not valid address');
ok($m->list_whitelist, 'list_whitelist');
ok($m->list, 'list');
ok($m->unwhitelist('postmaster@localhost'), 'whitelist');
ok($m->subscribe(1), 'subscribe1');
ok($m->list, 'list');
ok($m->subscribe(2), 'subscribe2');
ok($m->list, 'list');
ok($m->unsubscribe, 'unsubscribe');
ok($m->usage, 'usage');
ok($m->send, 'send')

