package MySpam::Email;
use strict;
use warnings;
use Carp qw(croak);
use Config::File;
use File::Basename;
use Sys::Syslog;
use File::Slurp;
use Time::HiRes qw(time);
use Mail::RFC822::Address qw(valid);
use POSIX qw(strftime);
use XML::API;
use Encode qw(decode);
use MySpam;
use MIME::Lite;
use HTML::Entities;


sub new {
    my $proto = shift;
    my $class = ref($proto) || $proto;
    my $self  = {};
    bless($self,$class);

    $self->{conffile} = shift || '/etc/myspam/myspam.conf';

    $self->reset;
    return $self;
}


sub connect {
    my $self = shift;
    return 1 if ($self->{myspam});

    eval {$self->{myspam} = MySpam->new($self->{conffile});};

    if ($@) {
        $self->{body}  = "Failed to connect to database: $@";
        $self->{xbody}->p("Failed to connect to database: $@");
        return;
    }
    return 1;
}


sub reset {
    my $self = shift;
    foreach my $key (keys %$self) {
        if ($key !~ m/(conffile)|(conf)|(css)|(myspam)|(start)/) {
            delete $self->{$key};
        }
    }

    $self->{start} = time;
    my $x = $self->{xbody} = XML::API->new(doctype => 'xhtml');
    $x->body_open;
    $self->{body} = '';
    return;
}


sub from {
    my $self    = shift;
    $self->{from} = shift || croak 'usage: from($address)';
}


sub to {
    my $self    = shift;
    $self->{to} = shift || croak 'usage: to($address)';
    $self->{xbody}->h1("MySpam for $self->{to}");
    $self->{body} .= "MySpam for $self->{to}\n\n";
}


sub cc {
    my $self    = shift;
    $self->{cc} = shift || croak 'usage: cc($address)';
}


sub subject {
    my $self    = shift;
    $self->{subject} = shift || croak 'usage: subject($subject)';
}


sub xbody {
    my $self = shift;
    return $self->{xbody};
}


sub add_to_body {
    my $self = shift;
    $self->{body} .= (shift);
}


sub usage {
    my $self = shift;

    $self->{body} .= "Available commands:\n\n";
    $self->{xbody}->p("Available commands are:");

    $self->{xbody}->table_open();
    foreach (
        ['help', 'display this list of commands'],
        ['list', 'List the mail stored in the quarantine area'],
        ['release:<id>', 'Release quarantined mail with id <id>'],
        ['whitelist', 'List the current addresses in the whitelist'],
        ['whitelist:<address>', 'Add <address> to the whitelist'],
        ['unwhitelist:<address>', 'Remove <address> from the whitelist'],
        ['subscribe', 'subscribe to a weekly newsletter containing the list of quaranteened mails'],
        ['subscribe2', 'subscribe to a bi-weekly newsletter containing the list of quaranteened mails'],
        ['unsubscribe', 'unsubscribe from the weekly or bi-weekly newsletter'],
    ) {
        $self->{body} .= "$_->[0] - $_->[1]\n";

        $self->{xbody}->tr_open;
        $self->{xbody}->td(-class => 'command', $_->[0]);
        $self->{xbody}->td($_->[1]);
        $self->{xbody}->tr_close;
    }
    $self->{xbody}->table_close;
    return 1;
}


sub error {
    my $self = shift;
    my $error = shift;

    syslog('err', $error);

    return unless($self->{outbound});

    $self->{xbody}->p(-class => 'error', $error);
    $self->{body} .= $error;

    $self->{outbound}->replace(Subject =>
                          '(ERROR) Re: '. $self->{inbound}->header('Subject'));
    if ($self->{conf}->{admin}) {
        $self->{outbound}->replace(Cc => $self->{conf}->{admin});
    }
    $self->send;
    exit 0;
}


sub list {
    my $self     = shift;
    my $fromwhen = shift || 0;
    return unless($self->connect());

    my @recipients =
        $self->{myspam}->get_quarantined_mails($self->{to}, $fromwhen);

    my $x = $self->{xbody};


    if (!$fromwhen) {
        $self->{body} .= "\nThe following mail is held in quarantine:\n\n";
        $x->p("The following mail is held in quarantine:");
    }
    else {
        $self->{body} .= "\nThe following mail was quarantined since\n"
                      .  "the last newsletter:\n\n";
        $x->p("The following mail was quarantined since "
             ."the last newsletter:");
    }


    $x->table_open(-id => 'quarantine');
    $x->tr_open;
    $x->th('Date (UTC)');
    $x->th('From');
    $x->th('Subject');
    $x->th('Score');
    $x->th('Released');
    $x->tr_close;

    my $odd = 1;
    foreach my $recip (@recipients) {
        # text version
        $self->{body} .= "\n    Date: ".
                            strftime('%F %R', gmtime($recip->epoch));
        $self->{body} .= "\n    From: ". $recip->h_from;
        $self->{body} .= "\n Subject: ". $recip->h_subject;
        $self->{body} .= "\n      ID: ". $recip->id;
    
        (my $hfromname = $recip->h_from) =~ s/(<.*)|(\")|(^\s+)|(\s+$)//g;
        (my $hfrom = $recip->h_from) =~ s/(.*<)|(>.*)//g;

        # html version
        $x->tr_open(-class => $odd ? 'odd' : 'even');
        $x->td(-class => 'date', strftime('%F %R', gmtime($recip->epoch)));
        $x->td(-class => 'from', decode('MIME-Header',$recip->h_from));
        $x->td(-class => 'subject', decode('MIME-Header',$recip->h_subject));
        $x->td(-class => 'num', sprintf('%.1f', $recip->sa_score));

        if ($recip->released) {
            $self->{body} .= (strftime("\nReleased: \%F \%R\n\n",
                                        gmtime($recip->released) ));
            $x->td_open(-class => 'released');
            $x->a(-href => "mailto:$self->{from}?subject=Release:" .
                   $recip->id, strftime('%F %R', gmtime($recip->released)));
            $x->td_close;
        }
        else {
            $self->{body} .= 
                "\n\nTo release send mailto:$self->{from}?subject=Release:".
                                $recip->id . "\n\n";

            $x->td_open(-class => 'released');
            $x->a(-href => "mailto:$self->{from}?subject=Release:" .
                     $recip->id,
                     'Release:' . $recip->id);
            $x->td_close;
        }
        $x->tr_close;
        $odd = $odd ? 0 : 1;

    } # foreach
    $x->table_close;

    $self->{body} .=
"\nSome mail clients (particularly Blackberries, and certain WebMail
applications) will not generate the correct email when you click on the
release link. In this situation simply copy the 'Release:12345678910'
text into the clipboard. Then compose a new email using your mail client
to $self->{from} and paste the Release:12345678910' text
(without the quotes) into the subject field.\n\n";

    $x->p_open("Some mail clients (particularly Blackberries, and certain "
        ."WebMail applications) will not generate the correct email when you"
        ." click on the release link. In this situation simply copy the"
        ." 'Release:12345678910' text into the clipboard. Then compose a new"
        ." email using your mail client to $self->{from} and paste the"
        ." 'Release:12345678910' text (without the quotes) into the subject"
        ." field.");

    $self->{body} .= "Current Whitelist\n";
    $x->h2("Current Whitelist");
    $x->p_open;

    my @wl = $self->{myspam}->get_whitelist($self->{to});
    foreach my $w (@wl) {
        $self->{body} .= ' '. $w->sender . "\n";
        $x->_add($w->sender);
        $x->br;
    }
    if (!@wl) {
        $self->{body} .= " None\n\n";
        $x->_add('None');
    }
    $x->p_close;


    $self->{body} .= "Subscription Status\n";
    $x->h2("Subscription Status");
    $x->p_open;

    my $sub = $self->{myspam}->get_subscriber($self->{to});
    if (!$sub) {
        $self->{body} .= " None\n\n";
        $x->_add('None');
    }
    else {
        if ($sub->period == 1) {
            $self->{body} .= ' Subscribed to the Weekly newsletter' . "\n";
            $x->_add('Subscribed to the Weekly newsletter');
        }
        else {
            $self->{body} .= ' Subscribed to the Bi-Weekly newsletter' . "\n";
            $x->_add('Subscribed to the Bi-Weekly newsletter');
        }
        $x->br;
    }
    $x->p_close;

    return 1;
}


sub release {
    my $self = shift;
    my $id   = shift || croak 'usage: release($id)';
    $self->{to} || croak 'must set to() before calling release';
    return unless($self->connect());

    my $x = $self->{xbody};

    if (my $recip = $self->{myspam}->release($self->{to}, $id)) {
        $self->{body} .= "\nThe following mail has been released.\n";
        $self->{body} .= "\n    Date: ".
                            strftime('%F %R', gmtime($recip->epoch));
        $self->{body} .= "\n    From: ". $recip->h_from;
        $self->{body} .= "\n Subject: ". $recip->h_subject;
        $self->{body} .= "\n      ID: ". $recip->id;

        $x->p("The following mail has been released");
        $x->table_open(-id => 'quarantine');

        $x->tr_open;
        $x->th('Date (UTC)');
        $x->th('From');
        $x->th('Subject');
        $x->th('Score');
        $x->th('Released');
        $x->tr_close;

        $x->tr_open(-class => 'odd');
        $x->td(-class => 'date', strftime('%F %R', gmtime($recip->epoch)));
        $x->td(-class => 'from', decode('MIME-Header',$recip->h_from));
        $x->td(-class => 'subject', decode('MIME-Header',$recip->h_subject));
        $x->td(-class => 'num', sprintf('%.1f', $recip->sa_score));
        $x->td_open(-class => 'released');
        $x->a(-href => "mailto:$self->{from}?subject=Release:" .
               $recip->id, strftime('%F %R', gmtime($recip->released)));
        $x->td_close;

        $x->tr_close();

        $x->table_close();

        return 1;
    }
    else {
        $self->{body} .= "\nMail with id '$id' could NOT be released.\n";
        $x->p("Mail with id '$id' could NOT be released");
        return;
    }

}


sub whitelist {
    my $self = shift;
    my $sender = shift || croak 'usage: whitelist($sender)';
    $self->{to} || croak 'must set to() before calling whitelist';
    return unless($self->connect());

    my $x = $self->{xbody};

    if (!valid($sender)) {
        $self->{body} .= "\n'$sender' is not a valid email address to whitelist\n";
        $x->p("\n'$sender' is not a valid email address to whitelist.\n");
        return;
    }

    if ($self->{myspam}->add_to_whitelist($self->{to}, $sender)) {
        $self->{body} .= "\n'$sender' has been whitelisted.\n";
        $self->{body} .= "Please allow 30 minutes for this to to be effective.\n";
        $x->p("$sender has been whitelisted. "
            . "Please allow 30 minutes for this to to be effective."
        );
        return 1;
    }

    $self->{body} .= "\n$sender could NOT be whitelisted.\n";
    $x->p("\n$sender could NOT be whitelisted.\n");
    return;
}


sub unwhitelist {
    my $self = shift;
    my $sender = shift || croak 'usage: whitelist($sender)';
    $self->{to} || croak 'must set to() before calling whitelist';
    return unless($self->connect());

    my $x = $self->{xbody};

    if ($self->{myspam}->remove_from_whitelist($self->{to}, $sender)) {
        $self->{body} .= "\n'$sender' is no longer in the whitelist.\n";

        $x->p("$sender is no longer in the whitelist.");
        return 1;
    }
    $self->{body} .= "\n$sender could NOT be unwhitelisted.\n";
    $x->p("\n$sender could NOT be unwhitelisted.\n");
    return;
}


sub unsubscribe {
    my $self = shift;
    $self->{to} || croak 'must set to() before calling unsubscribe';
    return unless($self->connect());

    my $x = $self->{xbody};

    if ($self->{myspam}->unsubscribe($self->{to})) {
        $self->{body} .= "\n'$self->{to}' has been unsubscribed.\n";

        $x->p("$self->{to} has been unsubscribed.");
        return 1;
    }
    $self->{body} .= "\n$self->{to} could NOT be unsubscribed.\n";
    $x->p("\n$self->{to} could NOT be unsubscribed.\n");
    return;
}


sub subscribe {
    my $self = shift;
    my $list = shift || croak 'usage: subscribe($list)';
    $self->{to} || croak 'must set to() before calling unsubscribe';
    return unless($self->connect());

    my $x = $self->{xbody};

    if ($self->{myspam}->subscribe($self->{to}, $list)) {
        $self->{body} .= "\n'$self->{to}' has been subscribed$list.\n";

        $x->p("$self->{to} has been subscribed$list.");
        return 1;
    }
    $self->{body} .= "\n$self->{to} could NOT be subscribed$list.\n";
    $x->p("\n$self->{to} could NOT be subscribed$list.\n");
    return;
}


sub send {
    my $self = shift;
    if ($self->{send}) {
        croak 'Should not send same mail twice';
    }
    $self->{send} = 1;

    if (!$self->{conf}) {
        $self->{conf} = Config::File::read_config_file($self->{conffile});
    }

    if (!$self->{css} and -r '/etc/myspam/myspam.css') {
        $self->{css} = read_file('/etc/myspam/myspam.css');
    }


    my $mail = MIME::Lite->new(
        From    => "MySpam <$self->{from}>",
        To      => $self->{to},
        Subject => $self->{subject},
        ($self->{cc} ? (Cc => $self->{cc}) : ()),
        Type    => 'multipart/alternative',
    );

    my $delta = time - $self->{start};

    if ($self->{conf}->{admin}) {  
        $self->{body} .= "\nIf you have questions about this mail recovery "
                   . "mechanism\n please contact your local IT support or "
                   . $self->{conf}->{admin}."\n\n";
    }
    if ($delta) {
        $self->{body} .= sprintf("Response generated in %.3f seconds", $delta);
    }
    $mail->attach(Type => 'TEXT', Data => $self->{body});


    my $xbody = $self->{xbody};
    if ($self->{conf}->{admin}) {  
        $xbody->p_open(
            "If you have questions about this mail recovery mechanism ".
            "please contact your local IT support or ");
        $xbody->a(-href => 'mailto:' . $self->{conf}->{admin},
              $self->{conf}->{admin});
        $xbody->p_close;
    }
    if ($delta) {
        $xbody->p(-class => 'timing',
            sprintf("Response generated in %.3f seconds", $delta));
    }


    my $x = XML::API->new(doctype => 'xhtml');
    $x->_set_lang('en');
    $x->html_open;
    $x->head_open;
    $x->title("MySpam Response");
    $x->style(-type => 'text/css', $self->{css}) if($self->{css});
    $x->head_close;
    $x->_add($xbody);


    my $tmp = $x->_as_string;
    $tmp =~ s/<\?xml.*\?>//;
    $mail->attach(Type => 'text/html', Data => $tmp);

    eval {
        $mail->send('sendmail');
    };
    if ($@) {
        openlog(basename($0), 'pid,ndelay', 'mail');
        syslog('err', "Could not send mail: $@");
        return;
    }
    return 1;
}




1;
__END__

=head1 NAME

MySpam::Email - Email Interface Module for the MySpam application

=head1 SYNOPSIS

  use MySpam::Email;
  my $e = MySpam::Email->new;

  $e->reset;
  $e->to($to);
  $e->from($from);
  $e->subject($subject);
  $e->list; # or release or whitelist or subscribe ... etc
  $e->send;

=head1 DESCRIPTION

B<MySpam::Email> is for generating a MySpam email response.
Various methods can be called to perform actions in the MySpam
database, and the results of those actions will be formatted as an email.

The email sent is a MIME multipart/alternative mail containing both
text/plain and text/html parts.

B<MySpam::Email> is used by the L<myspam-smtp> script.

=head1 METHODS

=head2 new($file)

Create a new B<MySpam::Email> object. Takes an optional $file argument
to specify a configuration file other than the default
/etc/myspam/myspam.conf.

=head2 connect()

Internal method. Creates a L<MySpam> object which automatically connects
to the database specified by /etc/myspam/myspam.conf or the $file given
to the new() method.

=head2 reset()

Resets all internal values ready for a new email to be generated. This
should be called after the send() method if you want to continue to use
the same object for more emails.

=head2 from($from)

Set the From: header.

=head2 to($to)

Set the To: header.

=head2 cc($cc)

Set the Cc: header.

=head2 subject($subject)

Set the Subject: header.

=head2 xbody()

Internal method. Returns the L<XML::API> object representing the HTML
part of the email.

=head2 add_to_body($text)

Internal method. Adds $text to the text/plain part of the email.

=head2 usage()

Generates a general help/usage statement.

=head2 error($msg)

Adds the text $msg to the body and includes the 'admin' address in the
Cc: header.

=head2 list()

Lists the mails contained in the database for the address $to (set by
the to() method). Croaks if to() has not already been called.

=head2 release($id)

Releases the mail with id $id if that mail is quarantined for to $to.
Croaks if to() has not already been called.

=head2 whitelist($sender)

Adds address $sender to the whitelist for $to.
Croaks if to() has not already been called.

=head2 unwhitelist($sender)

Removes address $sender from the whitelist for $to.
Croaks if to() has not already been called.

=head2 unsubscribe()

Unsubscribes address $to from all subscription lists.
Croaks if to() has not already been called.

=head2 subscribe(1|2)

Subscribe address $to to the subscription '1' or '2'. See L<myspam>
for the meanings of the different subscriptions.

=head2 send()

Hands off the email to the local MTA for delivery to the $to and/or $cc
addresses.


=head1 FILES

/etc/myspam/myspam.conf - database connection information

/etc/myspam/myspam.css - style definition for HTML email

/var/log/mail.* - syslog(8) reporting of success or failure

=head1 SEE ALSO

L<myspam-smtp>, L<myspam>, L<MySpam>

=head1 AUTHOR

Mark Lawrence E<lt>nomad@null.netE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2007 Mark Lawrence <nomad@null.net>

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

=cut

# vim: set tabstop=4 expandtab:
