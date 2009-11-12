use Test::More;
use strict;
use warnings;
use File::Slurp qw(read_file);
use Sys::Hostname;

BEGIN {
    unlink('t/myspamtest.db');
    unlink('t/whitelist.db');
    plan tests => 49;
}

END {
#    unlink('t/myspamtest.db');
}

use_ok('MySpam');

# Don't spam the testers
if( hostname ne 'lifebook' ) {
    no warnings 'redefine';
    no warnings 'once';
    *{MySpam::sendmail} = sub {1};
}

my $m = MySpam->new('t/test.conf');
isa_ok($m, 'MySpam');

$m->_debug(1);

can_ok($m, qw/
    new
    log
    error
    deploy
    quarantine_file
    quarantine
    get_quarantined_mails
    raw
    release
    remove
    sendmail
    add_to_whitelist
    remove_from_whitelist
    last_whitelist_epoch
    get_whitelist
    get_whitelist_all
    subscribe
    subscriber_sent
    unsubscribe
    get_subscriber
    expire
/);


ok($m->deploy, 'Tables deployed');

ok(!$m->last_whitelist_epoch, 'No whitelist epoch');
ok(!$m->get_whitelist('postmaster@localhost'), 'No whitelist yet');
ok($m->add_to_whitelist('postmaster@localhost', 'postmaster@localhost'),
    'Added to whitelist');
ok(!$m->add_to_whitelist('postmaster@localhost', 'not an address'),
    'Not a valid address');
ok($m->get_whitelist('postmaster@localhost'), 'In whitelist');
ok($m->add_to_whitelist('postmaster@localhost', 'mlawren@localhost'),
    'Added to whitelist');
ok($m->get_whitelist('postmaster@localhost'), 'In whitelist');
my @white = $m->get_whitelist('postmaster@localhost');
#isa_ok($white[0], 'Whitelist');
ok($white[0]->sender eq 'mlawren@localhost', 'sender is mlawren');
ok($white[0]->recipient eq 'postmaster@localhost', 'recipient is postmaster');

ok(!$m->get_whitelist('unknown@localhost'), 'Unknown not in whitelist');

ok($m->last_whitelist_epoch, 'have whitelist epoch');

ok($m->generate_whitelist_dbm('t/whitelist.dbm'), 'generated whitelist');
ok(-e 't/whitelist.dbm', 'whitelist exists');

ok($m->remove_from_whitelist('postmaster@localhost', 'postmaster@localhost'),
    'Removed from whitelist');
ok($m->remove_from_whitelist('postmaster@localhost', 'mlawren@localhost'),
    'Removed from whitelist');
ok(!$m->get_whitelist('postmaster@localhost'), 'Nothing in whitelist');


ok(!$m->get_subscriber('postmaster@localhost'), 'Not subscribed');
ok($m->unsubscribe('postmaster@localhost'), 'Not subscribed');
ok(!$m->get_subscriber('postmaster@localhost'), 'Not subscribed');
ok($m->subscribe('postmaster@localhost',1), 'Subscribed 1');
ok($m->get_subscriber('postmaster@localhost'), 'Subscribed');
ok($m->unsubscribe('postmaster@localhost'), 'Unsubscribed 1');
ok(!$m->get_subscriber('postmaster@localhost'), 'Unsubscribed');
ok($m->subscribe('postmaster@localhost',1), 'Subscribed 1');
ok($m->subscribe('postmaster@localhost',2), 'Subscribed 2');
ok($m->subscriber_newsletter_list, 'Newsletter list');
ok($m->subscriber_sent($m->subscriber_newsletter_list), 'subscriber updated');
ok(!$m->subscriber_newsletter_list, 'No Newsletter list');
ok($m->subscribe('postmaster@localhost',1), 'Subscribed 1');
ok($m->unsubscribe('postmaster@localhost'), 'Unsubscribed 2');


ok(!$m->get_quarantined_mails('postmaster@localhost'),
    'Nothing quarantined yet');

ok(!$m->release('postmaster@localhost',1), 'Nothing to release yet');

ok($m->quarantine_file('t/1189238618_spam'), 'File quarantined');
my $contents = read_file('t/1189238618_spam');
ok($m->quarantine($contents, 1189238618), 'Mail quarantined');

my @r = $m->get_quarantined_mails('postmaster@localhost');
ok(@r, 'Have quarantined mail');

my ($recipient, $raw) = $m->raw('postmaster@localhost',1);
is($raw,$contents, 'raw in and out');

ok($m->release('postmaster@localhost',1), 'Released a mail');
my $rel = $m->release('postmaster@localhost',1);
#isa_ok($rel, 'Recipient');

ok(!$m->release('unknown@localhost',1), 'Not Released someone elses mail');

ok($m->remove('postmaster@localhost',1), 'Removed a mail');
ok($m->remove('postmaster@localhost',1), 'Removed a mail, non-existent');

ok($m->add_to_whitelist('postmaster@localhost', 'mkp@clde.e.telefonica.net'),
    'Added to whitelist'); # This should release one

my ($dr,$dm) = $m->expire(time - 1189238518);
ok(!$dr, $dr . ' Recipients expired');
ok(!$dm, $dm . ' Messages expired');

($dr,$dm) = $m->expire(100);
ok($dr, $dr . ' Recipients expired');
ok($dm, $dm . ' Messages expired');
