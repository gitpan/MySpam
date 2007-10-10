package Mail::SpamAssassin::Plugin::WhitelistDBM;
use strict;
use warnings;
use Mail::SpamAssassin;
use Mail::SpamAssassin::Plugin;
use DB_File;
use Fcntl;
use GDBM_File;

our $VERSION = "0.07";
our @ISA = qw(Mail::SpamAssassin::Plugin);


sub new {
        my ($class, $permsgstatus) = @_;
        $class = ref($class) || $class;

        my $self = $class->SUPER::new($permsgstatus);
        bless ($self, $class);

    $self->{whitelistdbm} = '';
    $self->{mtime} = 0;
    $self->register_eval_rule ("whitelistdbm_from_to");

    dbg ("WhitelistDBM: Done constructor");
    return $self;
}


#
# this gets called as each parameter in the .cf file is encountered.
#
sub parse_config {
        my ($self, $config) = @_;
    if ($config->{key} eq 'whitelistdbm') {
        $self->{whitelistdbm} = $config->{value};
        return 1;
    }
    dbg ("WhitelistDBM: : Done parse_config");
}


sub create_dbm_session {
    my ($self, $permsgstatus) = @_;

    # clean up any possible leftover from previous sessions
    undef %{$self->{spamlist}};

    my @filestat = stat($self->{whitelistdbm});
    dbg ("WhitelistDBM: t88 $filestat[9], $self->{mtime}\n");

    if ((! tied %{$self->{spamlist}}) || ($filestat[9]>$self->{mtime})) {
        if ( tied %{$self->{spamlist}} ) {
            undef %{$self->{spamlist}};
            untie (%{$self->{spamlist}});
        }

        dbg ("WhitelistDBM: tieing DBM to hash,
             $filestat[9], $self->{mtime}\n");

        if (!tie (%{$self->{spamlist}},"GDBM_File",
                $self->{whitelistdbm}, &GDBM_READER,0444)) {
            die "Can't read $self->{whitelistdbm}: $!\n";
        }

        @filestat = stat($self->{whitelistdbm});
        $self->{mtime} = $filestat[9];
    }

    if ( ! tied %{$self->{spamlist}} ) {
        dbg ("WhitelistDBM: Could not tie to $self->{whitelistdbm}\n");
        return 0;
    } else {
        dbg ("WhitelistDBM: tied to $self->{whitelistdbm}\n");
    }
    return 1;
}


sub whitelistdbm_from_to {
    my ($self, $permsgstatus) = @_;
    dbg ("WhitelistDBM: Entering whitelistdbm_from_to\n");

    # Need From: and To. Adresses
    if ( $self->get_addr($permsgstatus) == 0 ) {
        return 0;
    }

    # Run rule only once per Mail
    $self->init($permsgstatus);

    SEARCH: foreach my $f_addr (@{$self->{from_addr}}) {
        # Check for valid email-adress (catches most of the
        # valid addresses)
        my $regex = qr/^[\w-]+(?:\.[\w-]+)*@(?:[\w-]+\.)+[a-zA-Z]{2,7}$/o;
        next unless ( $f_addr =~ m/$regex/ );

        foreach my $t_addr (@{$self->{to_addr}}) {
            next unless ( $t_addr =~ m/$regex/ );

            my $key = lc($f_addr).'|'.$t_addr;

            dbg ("WhitelistDBM: t8 $f_addr,$t_addr,$key\n");

            if ( exists $self->{spamlist}->{$key} ) {
                dbg ("WhitelistDBM: t9 $f_addr,$t_addr,$key\n");

                my $rule = 'WHITELISTDBM_FROM_TO';
                my $score = $permsgstatus->{conf}->{scores}->{$rule};
                $permsgstatus->_handle_hit(
                    $rule,
                    $score,
                    'HEADER: ',
                    $permsgstatus->{conf}->{descriptions}->{$rule}
                );

                #Yet another magic call
                #The for loop is necessary to set all 4 values
                for my $set (0..3) {
                    $permsgstatus->{conf}->{scoreset}->[$set]->{$rule} =
                        sprintf("%0.3f", $score);
                }
                last SEARCH;
            }
        }
    }

    dbg ("WhitelistDBM: done whitelistdbm_from_to");
    return $permsgstatus->{whitelistdbm_from_to};
}


sub get_addr {
        my ($self, $permsgstatus) = @_;

    dbg ("WhitelistDBM: Entering get_addr\n");

    @{$self->{from_addr}}=();
    foreach my $addr ($permsgstatus->all_from_addrs()) {
        push (@{$self->{from_addr}},$addr);
        dbg ("WhitelistDBM: from- $addr\n");
    }

    @{$self->{to_addr}}=();
    foreach my $addr ($permsgstatus->all_to_addrs()) {
        push (@{$self->{to_addr}},$addr);
        dbg ("WhitelistDBM: to- $addr\n");
    }

        # No From, no action
        #
        if (! scalar @{$self->{from_addr}} >0 ) {
                dbg ("WhitelistDBM\: No From-Adress found, terminating");
                return 0;
        }

        # No To, no action
        #
        if (! scalar @{$self->{to_addr}} >0 ) {
                dbg ("WhitelistDBM\: No To-Adress found, terminating");
                return 0;
        }
        dbg ("WhitelistDBM: done get_addr");
        return 1;
}


sub init {
        my ($self, $permsgstatus) = @_;
    dbg ("WhitelistDBM: Entering init\n");

        # set the default return code values
        #
    $permsgstatus->{whitelistdbm_from_to} = 0;

    # see if an DBM session is already active
    my @filestat = stat($self->{whitelistdbm});
    dbg ("WhitelistDBM: t87 $filestat[9], $self->{mtime}\n");
    if (( ! tied %{$self->{spamlist}}) || ($filestat[9]>$self->{mtime})) {

        # try to create a session
        if ($self->create_dbm_session($permsgstatus) == 0) {
            # unable to create a session so exit
            return 0;
        }
    }
    dbg ("WhitelistDBM:  done init");
}


sub dbg {
        Mail::SpamAssassin::dbg (@_);
}


1;
__END__

=head1 NAME

Mail::SpamAssassin::Plugin::WhitelistDBM - DBM From/To Whitelist

=head1 SYNOPSIS

  loadplugin Mail::SpamAssassin::Plugin::WhitelistDBM

=head1 DESCRIPTION

Whitelist based on From/To pairs stored in a DBM database.

This plugin checks a DBM database for combinations of From and To
adresses. If a match occurs, the score will be altered by +n or -n Points.

The format of the DBM database is as that used by the L<myspam> program.
Each key is a sender address (From) concatenated with '|' and the recipient
address (To).

  <From>|<To>

I have tried to write this plugin as generic as possible (given my
knoledge of Perl). It should be possible to add custom rules, defined
in a DBM-DB. See coments below.

A possible Configuration-File looks as follows:

  loadplugin Mail::SpamAssassin::Plugin::WhitelistDBM

  header          WHITELISTDBM_FROM_TO       eval:whitelistdbm_from_to()
  describe        WHITELISTDBM_FROM_TO       Dynamic From-To pairs
  score           WHITELISTDBM_FROM_TO       20.0

  whitelistdbm    /etc/myspam/whitelist.dbm

=head1 SEE ALSO

L<spamassassin>, L<myspam>

=head1 AUTHOR

Robert Meyer E<lt>r.meyer@net-wizard.org<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2007 Robert Meyer <r.meyer@net-wizard.org>

Based on Mail::SpamAssassin::Plugin::MYSQLList Copyright 2005
Eric A. Hall <ehall@ntrg.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

=cut

# vim: set tabstop=8 noexpandtab:
