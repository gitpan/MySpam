package MySpam;
use strict;
use warnings;
use Carp qw(croak);
use Sys::Syslog;
use File::Basename;
use Config::File;
use SQL::DB qw(define_tables max);
use File::Slurp qw(slurp);
use Email::Simple;
use MIME::Lite;
use Mail::RFC822::Address qw(valid);
use Compress::Bzip2 qw(memBzip memBunzip);
use File::Temp qw(tempfile);
use File::Copy;
use GDBM_File;


our $VERSION = '0.10';


define_tables(
    [
        table  => 'messages',
        class  => 'Message',
        column => [name => 'id',        type => 'INTEGER', primary => 1],
        column => [name => 'epoch',     type => 'INTEGER'],
        column => [name => 'sa_score',  type => 'FLOAT'],
        column => [name => 'ip',        type => 'VARCHAR(32)'],
        column => [name => 'mx_host',   type => 'VARCHAR(255)'],
        column => [name => 'raw',       type => 'MEDIUMBLOB'],
        type_mysql => 'InnoDB',
        index  => 'epoch',
    ],
    [
        table  => 'recipients',
        class  => 'Recipient',
        column => [name => 'id',        type => 'INTEGER', primary => 1],
        column => [name => 'epoch',     type => 'INTEGER'],
        column => [name => 'sender',    type => 'VARCHAR(255)'], # just email
        column => [name => 'email',     type => 'VARCHAR(255)'], # just email
        column => [name => 'h_from',    type => 'VARCHAR(255)'],
        column => [name => 'h_subject', type => 'VARCHAR(1024)'],
        column => [name => 'sa_score',  type => 'FLOAT'],
        column => [name => 'released',  type => 'INTEGER', default => 0],
        column => [name => 'message', type => 'INTEGER', ref => 'messages(id)'],
        unique => 'email,message',
        type_mysql => 'InnoDB',
        index  => 'email',
        index  => 'message',
    ],
    [
        table  => 'whitelist',
        class  => 'Whitelist',
        column => [name => 'epoch',     type => 'INTEGER'],
        column => [name => 'sender',    type => 'VARCHAR(255)'], # just email
        column => [name => 'recipient', type => 'VARCHAR(255)'], # just email
        unique => 'sender,recipient',
        type_mysql => 'InnoDB',
        index  => 'recipient',
        index  => 'sender,recipient',
    ],
    [
        table  => 'subscribers',
        class  => 'Subscriber',
        column => [name => 'subscriber', type => 'VARCHAR(255)', primary => 1],
        column => [name => 'period',     type => 'INTEGER', default => 1],
        column => [name => 'last_sent',  type => 'INTEGER', default => 0],
        type_mysql => 'InnoDB',
    ],
);


#
# Open up a reporting channel
#
openlog(basename($0), 'pid,ndelay', 'mail');



#
#
#
sub new {
    my $proto = shift;
    my $class = ref($proto) || $proto;
    my $self  = {};
    bless($self,$class);

    $self->{conffile} = shift || '/etc/myspam/myspam.conf';

    #
    # Configuration
    #
    $self->{conf} = Config::File::read_config_file($self->{conffile});
    my $conf = $self->{conf};

    my $db = SQL::DB->new();

    eval {
        $db->connect(
            $conf->{dbi},
            $conf->{user},
            $conf->{pass},
            { },
        );
    };

    if ($@) {
        $self->error("Database: $@");
        return;
    }

    $self->{db} = $db;
    return $self;
}


sub _debug {
    my $self = shift;
    $self->{debug} = shift;
}


sub db {
    my $self = shift;
    return $self->{db};
}


sub log {
    my $self = shift;
    syslog('info', shift || '*undef* '. join(':',caller));
}


sub error {
    my $self = shift;
    my $error = shift || '*undef* '. join(':',caller);
    if ($self->{debug}) {
        croak $error;
    }
    else {
        syslog('err', $error);
    }
}


sub deploy {
    my $self = shift;
    $self->{db}->deploy;
    $self->{db}->create_seq('message');
    $self->{db}->create_seq('recipient');
    return 1;
}


sub quarantine_file {
    my $self  = shift;
    my $file  = shift || croak 'usage: quarantine_file($filename)';
    my $epoch = time;

    if (basename($file) =~ m/^(\d+)_.*/) {
        $epoch = $1;
    }

    if (! -e $file) {
        $self->error($file . ' does not exist');
        return;
    }

    my $contents = slurp($file, err_mode => 'carp');

    if (!$contents) {
        $self->error("Could not read '$file'");
        return;
    }

    return $self->quarantine($contents, $epoch);
}


sub quarantine {
    my $self     = shift;
    my $contents = shift || croak 'usage: quarantine($contents, $epoch)';
    my $epoch    = shift || croak 'usage: quarantine($contents, $epoch)';

    my $email = Email::Simple->new($contents);
    if (!$email) {
        $self->error('No email found in contents');
        return;
    }

    (my $from = lc($email->header('From'))) =~ s/(.*<)|(>.*)|(^\")|(\"$)//g;
    (my $tmp  = lc($email->header('X-SA-Exim-Rcpt-To'))) =~ s/,/ /g;

    # grab the unique recipients
    my %seen = ();
    my @recipients = grep { ! $seen{$_} ++ } split(' ',$tmp);

    if (!@recipients) {
        $self->error('No X-SA-Exim-Rcpt-To recipients');
        return;
    }

    my $score = 0;
    if ($email->header('X-Spam-Status') =~ /score=([0-9\.]+)\s/) {
        $score = $1;
    };

    my $mx_host = 'unknown';
    if ($email->header('Received') =~ m/.* by\s(.*?)\s.*/) {
        $mx_host = $1;
    }

    
    my $res = $self->{db}->txn(sub{
        my $mid  = $self->{db}->seq('message');
        my @rids = $self->{db}->seq('recipient', scalar @recipients);

        my $message = Message->new({
            id            => $mid,
            epoch         => $epoch,
            sa_score      => $score,
            ip            => $email->header('X-SA-Exim-Connect-IP'),
            mx_host       => $mx_host,
            raw           => memBzip($contents,9),
        });
        $self->{db}->insert($message);

        foreach my $r (@recipients) {
            my $recipient = Recipient->new({
                id        => shift(@rids),
                epoch     => $epoch,
                email     => $r,
                sender    => $from,
                h_from    => $email->header('From') || 'Unknown',
                h_subject => $email->header('Subject') || '[none]',
                mx_host   => $mx_host || 'Unknown',
                sa_score  => $score || 0,
                message   => $mid,
            });
            $self->{db}->insert($recipient);
        }
    });

    unless ($res) {
        $self->error($res);
        return;
    }

    $self->log("$from => QUARANTINE(@recipients)");
    return 1;
}


sub get_quarantined_mails {
    my $self  = shift;
    my $email = lc(shift) || croak 'usage: get_quarantined_mails($address)';
    my $fromwhen = shift || 0;

    my $recipients = $self->{db}->arow('recipients');
    my @list = $self->{db}->fetch(
        select  => [$recipients->_columns],
        from     => $recipients,
        where    => ($recipients->email == $email) &
                    ($recipients->epoch > $fromwhen),
        order_by => $recipients->epoch,
    );
    return @list;
}


sub raw {
    my $self  = shift;
    my $email = shift || croak 'usage: raw($email,$id)';
    my $id    = shift || croak 'usage: raw($email,$id)';
    $email    = lc($email);

    my $r = $self->{db}->arow('recipients');
    my $m = $self->{db}->arow('messages');

    my $recipient = $self->{db}->fetch1(
        select   => [$r->_columns, $m->raw],
        from      => $r,
        left_join => $m,
        on        => $r->message == $m->id,
        where     => ($r->id == $id) & ($r->email == $email),
    );

    return unless ($recipient);
    return ($recipient, memBunzip($recipient->raw));
}


sub release {
    my $self  = shift;
    my $email = shift || croak 'usage: release($email,$id)';
    my $id    = shift || croak 'usage: release($email,$id)';
    $email    = lc($email);

    my $recipients = $self->{db}->arow('recipients');
    my $messages = $self->{db}->arow('messages');

    my $recipient = $self->{db}->fetch1(
        select   => [$recipients->_columns, $messages->raw],
        from      => $recipients,
        left_join => $messages,
        on        => $recipients->message == $messages->id,
        where     => ($recipients->id == $id) & ($recipients->email == $email),
    );

    my $raw;
    return unless ($recipient and $raw = memBunzip($recipient->raw));

    if (!$self->sendmail($email, $raw)) {
        $self->log($recipient->sender . " ** $email");
        return;
    }

    $self->log($recipient->sender . " => $email");
    $recipient->set_released(time);
    $self->{db}->update($recipient);

    return $recipient;
}


sub remove {
    my $self  = shift;
    my $email = shift || croak 'usage: release($email,$id)';
    my $id    = shift || croak 'usage: release($email,$id)';
    $email    = lc($email);

    my $res = $self->{db}->txn(sub{
        my $recipients = $self->{db}->arow('recipients');
        my $messages = $self->{db}->arow('messages');

        my $recipient = $self->{db}->fetch1(
            select   => [
                $recipients->id->as('rid'),
                $messages->id->as('mid')
            ],
            from      => $recipients,
            left_join => $messages,
            on        => $recipients->message == $messages->id,
            where     => ($recipients->id == $id) &
                         ($recipients->email == $email),
        );

        if (!$recipient) {
            return 1;
        }

        my $d1 = $self->{db}->do(
            delete_from => $messages,
            where       => $messages->id == $recipient->mid,
        );

        my $d2 = $self->{db}->do(
            delete_from => $recipients,
            where       => $recipients->id == $recipient->rid,
        );

        if ($d1 and $d2) {
            $self->log("Deleted $id for $email");
            return 1;
        }

        $self->log("Delete $id for $email: FAILED (unknown error)");
        die "Delete $id for $email: FAILED (unknown error)";
    });
    return $res;
}


sub sendmail {
    my $self = shift;
    my $to   = shift || croak 'usage: sendmail($to,$text)';
    my $mail = shift || croak 'usage: sendmail($to,$text)';

    if (!open(MAIL, '| /usr/sbin/sendmail -oi -n "' . $to . '"')) {
        $self->error("open: $!");
        return;
    }

    if (print MAIL $mail) {
        close(MAIL); 
        return 1;
    }

    $self->error("print: $!");
    close(MAIL); 
    return;
}


sub add_to_whitelist {
    my $self      = shift;
    my $recipient = shift || croak 'usage add_to_whitelist($recipient,$sender)';
    my $sender    = shift || croak 'usage add_to_whitelist($recipient,$sender)';

    $sender       = lc($sender);
    $recipient    = lc($recipient);
    $sender       =~ s/^<(.*)>$/$1/;
    $recipient    =~ s/^<(.*)>$/$1/;

    # Make sure sender is valid email address or a domain match
    if (!valid($sender) && $sender !~ /^\*\@/) {
        return;
    }

    # First of all check if this already exists
    my $wl = $self->{db}->arow('whitelist');
    my @list = $self->{db}->fetch(
        select  => [$wl->_columns],
        from    => $wl,
        where   => ($wl->sender == $sender) & ($wl->recipient == $recipient),
    );
    return 1 if (@list);

    # Otherwise create/insert
    my $whitelist = Whitelist->new({
        epoch     => time,
        sender    => $sender,
        recipient => $recipient
    });

    eval {$self->{db}->insert($whitelist);};

    if ($@) {
        $self->error($@);
        return;
    }

    $self->log("Whitelisted $sender => $recipient");

    # Since this address is now whitelisted, lets release all the
    # matching mails in the quarantine

    my $recipients = $self->{db}->arow('recipients');
    @list = $self->{db}->fetch(
        select => [
            $recipients->id
        ],
        from   => $recipients,
        where  => ($recipients->email == $recipient) &
                  ($recipients->sender == $sender),
    );

    foreach my $mail (@list) {
        $self->release($recipient, $mail->id);
    }

    return 1;

}


sub remove_from_whitelist {
    my $self      = shift;
    my $recipient = shift ||
        croak 'usage add_to_whitelist($recipient,$sender)';
    my $sender    = shift ||
        croak 'usage add_to_whitelist($recipient,$sender)';

    $sender       = lc($sender);
    $recipient    = lc($recipient);

    # First of all check if this pair doesn't exist
    my $wl = $self->{db}->arow('whitelist');
    my $item = $self->{db}->fetch1(
        select  => [$wl->epoch],
        from    => $wl,
        where   => ($wl->sender == $sender) & ($wl->recipient == $recipient),
    );
    return 1 unless ($item);

    my $res = eval {$self->{db}->do(
        delete => $wl,
        where   => ($wl->sender == $sender) & ($wl->recipient == $recipient),
    )};

    if ($res) {
        $self->log("Un-Whitelisted $sender => $recipient");
        return 1;
    }

    $self->error($@);
    return;
}


sub last_whitelist_epoch {
    my $self = shift;

    my $wl = $self->{db}->arow('whitelist');
    my @last = $self->{db}->fetch(
        select => max($wl->epoch)->as('max_epoch'),
        from   => $wl
    );

    if (@last) {
        return $last[0]->max_epoch || 0;
    }
    return 0;
}


sub get_whitelist {
    my $self      = shift;
    my $recipient = shift || croak 'usage get_whitelist($recipient)';
    $recipient    = lc($recipient);

    my $r = $self->{db}->arow('whitelist');
    my @list = $self->{db}->fetch(
        select  => [$r->_columns],
        from     => $r,
        where    => $r->recipient == $recipient,
        order_by => $r->sender,
    );
    return @list;
}


sub get_whitelist_all {
    my $self      = shift;

    my $r = $self->{db}->arow('whitelist');
    return $self->{db}->fetch(
        select  => [$r->_columns],
        from     => $r,
        order_by => $r->sender,
    );
}


sub generate_whitelist_dbm {
    my $self = shift;
    my $file = shift || $self->{conf}->{whitelist} ||
        croak 'no file given and no whitelist option defined';

    my %entries;
    my ($fh, $tempfile) = tempfile();
    tie %entries, 'GDBM_File', $tempfile, &GDBM_WRCREAT, 0644;

    my $i = 0;
    foreach my $entry ($self->get_whitelist_all) {
        $entries{$entry->sender .'|'. $entry->recipient} = 1;
        $i++;
    }

    untie %entries;

    if (!move($tempfile, $file)) {
        $self->error("move($tempfile,$file): $!");
        return;
    }

    if (!chmod(0644,$file)) {
        $self->error("chmod(0644,$file): $!");
        return;
    }

    $self->log("Generated $i whitelist entries");
    return $i || '0E0';
}


sub subscribe {
    my $self   = shift;
    my $email  = shift || croak 'usage: subscribe($email, $days)';
    my $days = shift || croak 'usage: subscribe($email, $days)';
    $email     = lc($email);

    # First of all check if this already exists
    my $s = $self->{db}->arow('subscribers');

    my ($item) = $self->{db}->fetch(
        select => [$s->_columns],
        from   => $s,
        where  => $s->subscriber == $email,
    );

    if ($item) {
        $item->set_period($days);
        eval{ $self->{db}->update($item);};
        if ($@) {
            $self->error($@);
            return;
        }
        return 1;
    }

    $item = Subscriber->new({
        subscriber => $email,
        period => $days,
    });

    eval{ $self->{db}->insert($item);};
    if ($@) {
        $self->error($@);
        return;
    }
    return 1;
}


sub get_subscriber {
    my $self  = shift;
    my $email = shift || croak 'usage: get_subscriber($email)';
    $email    = lc($email);

    my $r = $self->{db}->arow('subscribers');
    return $self->{db}->fetch1(
        select => [$r->_columns],
        from   => $r,
        where  => $r->subscriber == $email,
    );
}


sub subscriber_sent {
    my $self       = shift;
    my $subscriber = shift || die "missing subscriber";

    $subscriber->set_last_sent(time);

    if (!eval{$self->{db}->update($subscriber);}) {
        $self->error($@);
        return;
    }
    return 1;
}


sub subscriber_newsletter_list {
    my $self = shift;

    my $now    = time;
    my $day_in_seconds = 60*60*24;

    my $subscribers = $self->{db}->arow('subscribers');

    my @list = $self->{db}->fetch(
        select => [
            $subscribers->_columns,
        ],
        from   => $subscribers,
        where  => ($subscribers->period * $day_in_seconds) <
                  ($now - $subscribers->last_sent)
    );
    return @list;
}


sub unsubscribe {
    my $self  = shift;
    my $email = shift || croak 'usage: unsubscribe($email)';
    $email    = lc($email);

    my $s = $self->{db}->arow('subscribers');

    eval {$self->{db}->do(
        delete => $s,
        where  => $s->subscriber == $email,
    )};

    if ($@) {
        $self->error($@);
        return;
    }

    return 1;
}



sub expire {
    my $self = shift;
    my $age  = shift || $self->{conf}->{expire} || return;

    my $r = $self->{db}->arow('recipients');
    my $rr = $self->{db}->do(
        delete   => $r,
        where    => $r->epoch < (time - $age),
    );

    my $m = $self->{db}->arow('messages');
    my $mm = $self->{db}->do(
        delete   => $m,
        where    => $m->epoch < (time - $age),
    );

    $rr = $rr + 0;
    $mm = $mm + 0;
    $self->log("Expired $mm messages $rr recipients");
    return ($rr,$mm);
}


1;
__END__

=head1 NAME

MySpam - Database operations for the MySpam application

=head1 SYNOPSIS

  use MySpam;
  my $m = MySpam->new;

  $m->deploy;
  $m->quarantine($recipient, $text);
  $m->get_quarantined_mails($address);
  $m->release($address, $id);
  $m->add_to_whitelist($address, $sender);
  $m->remove_from_whitelist($address, $sender);

  # and other methods as below ...

=head1 DESCRIPTION

B<MySpam> is the database interface for the myspam application. The API
enables the programmer to quarantine mails, retrieve them, set user
whitelists, subscribe emails, etc.

The SQL used is fairly standard, known to work on at least SQLite and
MySQL databases.

=head1 METHODS

=head2 new($file)

Create a new MySpam object. Takes an optional $file parameter to specify
a config file location. If $file is not given the default
/etc/myspam/myspam.conf is used. This method connects to the database
as defined in the config file.  Returns undef upon failure.

=head2 db

Return the underlying database connection (an L<SQL::DB> object)

=head2 log($msg)

Write to the syslog with level 'info'.

=head2 error($msg)

Write to the syslog with level 'error'.

=head2 deploy

Create the needed tables in the database.

=head2 quarantine_file($file)

Save the file $file containing an email to the database. Returns true if
successful, undefined otherwise. Expects the filename to be
<epoch>_.* where <epoch> is the number of seconds since 1 January 1970.
(The same format that sa-exim uses).

=head2 quarantine($epoch, $text)

Save the email contained in $text to the database with an epoch of
$epoch. Returns true if successful, undefined otherwise.

=head2 get_quarantined_mails($address)

Returns the list of recipient objects that have the email address
$address. See DATABASE SCHEMA below for the methods of the recipient
objects.

=head2 raw($email, $id)

Return a tuple of ($recipient, $raw_text) for mail identified by
($id,$email). See DATABASE SCHEMA below for the methods of the
$recipient object.

=head2 release($email, $id)

Forwards the mail identified by ($email,$id) to address $email.
Returns the matching Recipient object.

=head2 remove($email, $id)

Removes the mail identified by $email,$id from the database. Returns
true if the mail was deleted or did not exist, false otherwise.

=head2 sendmail($to, $text)

Internal method. Calls /usr/sbin/sendmail to deliver $text to $to.

=head2 add_to_whitelist($recipient, $sender)

Adds email address $sender to the whitelist for $recipient (where
$recipient is an email address). Be aware that the arguments here are
in the reverse order to what you would expect.

=head2 remove_from_whitelist($recipient, $sender)

Removes email address $sender from the whitelist of $recipient (where
$recipient is an email address). Be aware that the arguments here are
in the reverse order to what you would expect.

=head2 get_whitelist($recipient)

Returns the list of Whitelist objects for address $recipient.
See DATABASE SCHEMA below for the methods of the returned objects.

=head2 get_whitelist_all

Returns all Whitelist objects.
See DATABASE SCHEMA below for the methods of the returned objects.

=head2 generate_whitelist_dbm($file)

Creates a Berkeley DBM file with a list of <sender> <recipient> pairs
separated by a '|' as the key values. If $file is not given then the
the 'whitelist' configuration item is used. If neither exist/defined
then this method croaks.

=head2 subscribe($email, $days)

Subscribes $email to the newsletter, to be received every $days days.
Automatically unsubscribes from all other lists if subscribed
elsewhere.

=head2 get_subscriber($email)

Return the Subscriber object (if it exists) for $email.
See DATABASE SCHEMA below for the methods of the returned objects.

=head2 subscriber_sent($subscriber)

Updates the time sent value to the current time for subscriber $subscriber.

=head2 subscriber_newsletter_list

Returns the list of subscriber objects that are due for a newsletter
as of the current time.

=head2 unsubscribe($email)

Unsubscribes $email from all subscription lists.

=head2 expire($age)

Deletes all quarantined objects that are older than $age. Returns a
tuple of ($number_messages_deleted, $number_recipients_deleted).
If the optional $age is not specified then the 'expire' configuration
option is used instead.

=head1 DATABASE SCHEMA

  CREATE TABLE messages (
      id              INTEGER        NOT NULL,
      epoch           INTEGER        NOT NULL,
      sa_score        FLOAT          NOT NULL,
      ip              VARCHAR(32)    NOT NULL,
      mx_host         VARCHAR(255)   NOT NULL,
      raw             MEDIUMBLOB     NOT NULL,
      PRIMARY KEY(id)
  );

  CREATE INDEX messages_epoch ON messages (epoch);

  CREATE TABLE recipients (
      id              INTEGER        NOT NULL,
      epoch           INTEGER        NOT NULL,
      sender          VARCHAR(255)   NOT NULL,
      email           VARCHAR(255)   NOT NULL,
      h_from          VARCHAR(255)   NOT NULL,
      h_subject       VARCHAR(1024)  NOT NULL,
      sa_score        FLOAT          NOT NULL,
      released        INTEGER        NOT NULL DEFAULT 0,
      message         INTEGER        NOT NULL REFERENCES messages(id),
      PRIMARY KEY(id),
      UNIQUE (email, message)
  );

  CREATE INDEX recipients_email ON recipients (email);

  CREATE INDEX recipients_message ON recipients (message);

  CREATE TABLE whitelist (
      epoch           INTEGER        NOT NULL,
      sender          VARCHAR(255)   NOT NULL,
      recipient       VARCHAR(255)   NOT NULL,
      UNIQUE (sender, recipient)
  );

  CREATE INDEX whitelist_recipient ON whitelist (recipient);

  CREATE INDEX whitelist_sender_recipient ON whitelist (sender,recipient);

  CREATE TABLE subscribers (
      subscriber      VARCHAR(255)   NOT NULL,
      period          INTEGER        NOT NULL DEFAULT 1,
      last_sent       INTEGER        NOT NULL DEFAULT 0,
      PRIMARY KEY(subscriber)
  );

  CREATE TABLE sqldb (
      name            VARCHAR(32)    NOT NULL UNIQUE,
      val             INTEGER        NOT NULL
  );


=head1 FILES

/etc/myspam/myspam.conf - database connection information

/var/log/mail.* - syslog(8) reporting of success or failure

=head1 SEE ALSO

L<myspam>, L<MySpam::Email>, L<SQL::DB>

=head1 AUTHOR

Mark Lawrence E<lt>nomad@null.netE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright 2006-2009 Mark Lawrence <nomad@null.net>

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

=cut

# vim: set tabstop=4 expandtab:
