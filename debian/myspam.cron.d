# /etc/cron.d/myspam

#
# Quarantine mails every 5 minutes
#
*/5 * * * * Debian-exim  [ -x /usr/bin/myspam ] && /usr/bin/myspam quarantine /var/spool/sa-exim/SApermreject/new --rm > /dev/null

#
# Expire old mails once every day
#
1 7 * * * Debian-exim  [ -x /usr/bin/myspam ] && /usr/bin/myspam expire

#
# Generate a whitelist (for SpamAssassin) every half hour)
#
8,38 * * * * Debian-exim  [ -x /usr/bin/myspam ] && /usr/bin/myspam genwhitelist

#
# Send out the newsletter to subscribers once a week
#
3 22 * * Sun Debian-exim  [ -x /usr/bin/myspam ] && /usr/bin/myspam newsletter --send

