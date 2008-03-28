use inc::Module::Install;

license         'GPL';
name            'MySpam';
all_from        'lib/MySpam.pm';
abstract        'Manage SPAM mail quarantined by sa-exim';

build_requires  'Test::More'         => '0.42';
build_requires  'DBD::SQLite'        => 0; # for tests

requires        'Time::HiRes'        => 0;
requires        'LockFile::Simple'   => 0;
requires        'Config::File'       => 0;
requires        'Email::Simple'      => 0;
requires        'Mail::RFC822::Address' => 0;
requires        'MIME::Lite'         => 0;
requires        'XML::API::XHTML'    => 0.17;
requires        'File::Slurp'        => 0;
requires        'SQL::DB'            => 0.13;
requires        'MIME::Base64'       => 0;
requires        'Compress::Bzip2'    => 0;
requires        'GDBM_File'          => 0;


install_script  'bin/myspam';
install_script  'bin/myspam-smtp';

auto_install;

WriteAll;

sub MY::postamble {
    return &Module::AutoInstall::postamble ."

VARLIB = \$(DESTDIR)/var/lib/myspam
CONF_DIR = \$(DESTDIR)/etc
CONF = \$(CONF_DIR)/myspam/myspam.conf
CSS = \$(CONF_DIR)/myspam/myspam.css
SPAM = \$(CONF_DIR)/spamassassin/whitelistdbm.cf

ROUTER_DIR = \$(DESTDIR)/etc/exim4/conf.d/router
ROUTER = \$(ROUTER_DIR)/10-myspam_router

TRANSPORT_DIR = \$(DESTDIR)/etc/exim4/conf.d/transport
TRANSPORT = \$(TRANSPORT_DIR)/40-myspam_transport

etc:
	-mkdir -p \$(VARLIB)
	-touch \$(VARLIB)/myspam.db

	-mkdir -p \$(CONF_DIR)/myspam
	-mkdir -p \$(CONF_DIR)/spamassassin
	-mkdir -p \$(ROUTER_DIR)
	-mkdir -p \$(TRANSPORT_DIR)

	if [ ! -s \$(CONF) ]; then \\
		install -m 600 conf/myspam.conf  \$(CONF); \\
	fi

	if [ ! -s \$(CSS) ]; then \\
		install -m 644 conf/myspam.css  \$(CSS); \\
	fi

	if [ ! -s \$(SPAM) ]; then \\
		install -m 644 conf/whitelistdbm.cf  \$(SPAM); \\
	fi

	if [ ! -s \$(ROUTER) ]; then \\
        install -m 644 conf/router \\
                        \$(ROUTER); \\
	fi
	if [ ! -s \$(TRANSPORT) ]; then \\
	    install -m 644 conf/transport \\
   	    \$(TRANSPORT); \\
	fi
"
}

