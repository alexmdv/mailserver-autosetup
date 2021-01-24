#!/bin/bash
# Read domain name
echo -n "Enter domain name (example.com):"
read -r mydomain
echo -n "Enter mail server hostname (mail):"
read -r myhostname
echo -n "Enter local IP address:"
read -r mylocalip

# Check names
echo -n "Full server name will be $myhostname.$mydomain Correct? (y/n)"
read -r mydomaincheck
if [[ "$mydomaincheck" != "y" ]]; then
echo -n "Aborted..."
echo
exit
fi

# Install packages
apt install -y argon2 pwgen postfix postfix-pgsql dovecot-imapd dovecot-pgsql dovecot-lmtpd dovecot-sieve dovecot-managesieved rspamd postgresql apache2 phppgadmin python3-certbot-apache php-curl php-dom php-json php-mail php-xml php-date

# Stop all unconfigured services
service apache2 stop; service postfix stop; service dovecot stop; service postgresql stop

# Delete all default sites from Apache
for i in /etc/apache2/sites-enabled/*; do a2dissite `basename $i`; done
rm -f /etc/apache2/sites-available/000-default.conf
rm -f /etc/apache2/sites-available/default-ssl.conf

# Disable phpPgAdmin configuration
a2disconf phppgadmin

# vhost for phpPgAdmin
rm -f /etc/apache2/sites-available/lanhost.conf

echo "<VirtualHost $mylocalip:80>" >> /etc/apache2/sites-available/lanhost.conf
echo "    Include /etc/apache2/conf-available/phppgadmin.conf" >> /etc/apache2/sites-available/lanhost.conf
echo "    DocumentRoot /var/www/lanhost" >> /etc/apache2/sites-available/lanhost.conf
echo "    ErrorLog \${APACHE_LOG_DIR}/lanhost.error.log" >> /etc/apache2/sites-available/lanhost.conf
echo "</VirtualHost>" >> /etc/apache2/sites-available/lanhost.conf

mkdir -m 640 /var/www/lanhost && chown www-data:www-data -R /var/www/lanhost

# phpPgAdmin access
mysearch="Require local"
myreplace="Require all granted"
sed -i "s/$mysearch/$myreplace/gi" /etc/apache2/conf-available/phppgadmin.conf

# public vhost
rm -f /etc/apache2/sites-available/webmail.conf

echo "<VirtualHost *:443>" >> /etc/apache2/sites-available/webmail.conf
echo "    ServerName $myhostname.$mydomain" >> /etc/apache2/sites-available/webmail.conf
echo "    DocumentRoot /var/www/webmail" >> /etc/apache2/sites-available/webmail.conf
echo "    <Directory \"/var/www/webmail\">" >> /etc/apache2/sites-available/webmail.conf
echo "        Options +FollowSymLinks -Indexes" >> /etc/apache2/sites-available/webmail.conf
echo "        AllowOverride All" >> /etc/apache2/sites-available/webmail.conf
echo "    </Directory>" >> /etc/apache2/sites-available/webmail.conf
echo "    <Directory \"/var/www/webmail/data/\">" >> /etc/apache2/sites-available/webmail.conf
echo "        Require all denied" >> /etc/apache2/sites-available/webmail.conf
echo "    </Directory>" >> /etc/apache2/sites-available/webmail.conf
echo "    SSLEngine on" >> /etc/apache2/sites-available/webmail.conf
echo "    SSLCertificateFile /etc/letsencrypt/live/$myhostname.$mydomain/fullchain.pem" >> /etc/apache2/sites-available/webmail.conf
echo "    SSLCertificateKeyFile /etc/letsencrypt/live/$myhostname.$mydomain/privkey.pem" >> /etc/apache2/sites-available/webmail.conf
echo "    Protocols h2 http/1.1" >> /etc/apache2/sites-available/webmail.conf
echo "    Header always set Strict-Transport-Security \"max-age=63072000\"" >> /etc/apache2/sites-available/webmail.conf
echo "    ErrorLog  \${APACHE_LOG_DIR}/webmail.port443.error.log" >> /etc/apache2/sites-available/webmail.conf
echo "</VirtualHost>" >> /etc/apache2/sites-available/webmail.conf

mkdir -m 640 /var/www/webmail && chown www-data:www-data -R /var/www/webmail

# HTTP to HTTPs redirect
rm -f /etc/apache2/sites-available/ssl-redirect.conf

echo "<VirtualHost *:80>" >> /etc/apache2/sites-available/ssl-redirect.conf
echo "    ServerName $myhostname.$mydomain" >> /etc/apache2/sites-available/ssl-redirect.conf
echo "    RewriteEngine On" >> /etc/apache2/sites-available/ssl-redirect.conf
echo "    RewriteCond %{HTTPS} off" >> /etc/apache2/sites-available/ssl-redirect.conf
echo "    RewriteRule (.*) https://%{HTTP_HOST}%{REQUEST_URI} [R=301]" >> /etc/apache2/sites-available/ssl-redirect.conf
echo "    ErrorLog \${APACHE_LOG_DIR}/ssl-redirect.error.log" >> /etc/apache2/sites-available/ssl-redirect.conf
echo "</VirtualHost>" >> /etc/apache2/sites-available/ssl-redirect.conf

# More Secure TLS
rm -i /etc/apache2/conf-available/ssl-stricter-options.conf

echo "SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1 -TLSv1.2" >> /etc/apache2/conf-available/ssl-stricter-options.conf
echo "SSLHonorCipherOrder off" >> /etc/apache2/conf-available/ssl-stricter-options.conf
echo "SSLSessionTickets off" >> /etc/apache2/conf-available/ssl-stricter-options.conf
echo "SSLUseStapling On" >> /etc/apache2/conf-available/ssl-stricter-options.conf
echo "SSLStaplingCache \"shmcb:logs/ssl_stapling(32768)\"" >> /etc/apache2/conf-available/ssl-stricter-options.conf

a2enconf ssl-stricter-options

# Disable Custom logs
a2disconf other-vhosts-access-log

# Mods
a2enmod rewrite ssl headers

# Starting Apache
a2ensite lanhost ssl-redirect

#Get SSL certificates
#certbot certonly --apache --agree-tos --email admin@$mydomain --no-eff-email --domain $myhostname.$mydomain

rm -f /etc/letsencrypt/renewal-hooks/deploy/reload_all_services_using_tls.sh

echo "#!/bin/bash" >> /etc/letsencrypt/renewal-hooks/deploy/reload_all_services_using_tls.sh
echo "apachectl graceful" >> /etc/letsencrypt/renewal-hooks/deploy/reload_all_services_using_tls.sh
echo "postfix reload" >> /etc/letsencrypt/renewal-hooks/deploy/reload_all_services_using_tls.sh
echo "dovecot reload" >> /etc/letsencrypt/renewal-hooks/deploy/reload_all_services_using_tls.sh


############################################
################ DATABASE ##################

# phpPgAdmin allow login for postgres
mysearch="extra_login_security'] = true;"
myreplace="extra_login_security'] = false;"
sed -i "s/$mysearch/$myreplace/gi" /etc/phppgadmin/config.inc.php

# phpPgAdmin - Max chars
mysearch="max_chars'] = 50;"
myreplace="max_chars'] = 120;"
sed -i "s/$mysearch/$myreplace/gi" /etc/phppgadmin/config.inc.php

# Remove peer authentication
mysearch="local   all             all                                     peer"
myreplace="#local   all             all                                     peer"
sed -i "s/$mysearch/$myreplace/gi" /etc/postgresql/11/main/pg_hba.conf

# Start PostgreSQL
service postgresql start

# DB Passwords
#echo pwgen 16 1

pgadmpass=$(pwgen 16 1)
pgmailuserpass=$(pwgen 16 1)

# set postres password
echo "ALTER ROLE postgres WITH ENCRYPTED PASSWORD '$pgadmpass';" | su -c "psql" postgres

echo "CREATE DATABASE mail_server;" | PGPASSWORD=$pgadmpass psql -U "postgres" -h 127.0.0.1

echo "CREATE DOMAIN local_part TEXT NOT NULL CHECK(LENGTH(VALUE) <= 64);" | PGPASSWORD=$pgadmpass psql -U "postgres" -d "mail_server" -h 127.0.0.1
echo "CREATE DOMAIN domain_part TEXT NOT NULL CHECK(LENGTH(VALUE) <= 253);" | PGPASSWORD=$pgadmpass psql -U "postgres" -h 127.0.0.1 -d "mail_server"
echo "CREATE DOMAIN user_input TEXT CHECK(LENGTH(VALUE) <= 256);" | PGPASSWORD=$pgadmpass psql -U "postgres" -h 127.0.0.1 -d "mail_server"

echo "CREATE TABLE domains (domain domain_part PRIMARY KEY);" | PGPASSWORD=$pgadmpass psql -U "postgres" -h 127.0.0.1 -d "mail_server"
echo "CREATE TABLE users (domain domain_part REFERENCES domains(domain) ON DELETE RESTRICT,local local_part NOT NULL,password_hash user_input,display_name user_input,PRIMARY KEY(domain, local),CHECK(char_length(local || domain) <= 254));" | PGPASSWORD=$pgadmpass psql -U "postgres" -h 127.0.0.1 -d "mail_server"
echo "CREATE TABLE aliases (source_local local_part NOT NULL,source_domain domain_part REFERENCES domains(domain) ON DELETE RESTRICT,destination_local local_part,destination_domain domain_part,PRIMARY KEY(source_local, source_domain),FOREIGN KEY (destination_local, destination_domain) REFERENCES users (local, domain) ON DELETE CASCADE,CHECK(char_length(source_local || source_domain) <= 254));" | PGPASSWORD=$pgadmpass psql -U "postgres" -h 127.0.0.1 -d "mail_server"
echo "CREATE TABLE shared_mailboxes (shared_mailbox_local local_part,shared_mailbox_domain domain_part,shared_to_local local_part,shared_to_domain domain_part,PRIMARY KEY (shared_mailbox_local, shared_mailbox_domain, shared_to_local, shared_to_domain),FOREIGN KEY (shared_mailbox_local, shared_mailbox_domain) REFERENCES users (local, domain) ON DELETE CASCADE,FOREIGN KEY (shared_to_local, shared_to_domain) REFERENCES users (local, domain) ON DELETE CASCADE);" | PGPASSWORD=$pgadmpass psql -U "postgres" -h 127.0.0.1 -d "mail_server"

echo "CREATE VIEW users_fqda AS SELECT users.local || '@' || domains.domain AS \"fqda\", users.password_hash, users.display_name FROM users, domains WHERE users.domain = domains.domain;" | PGPASSWORD=$pgadmpass psql -U "postgres" -h 127.0.0.1 -d "mail_server"
echo "CREATE VIEW aliases_fqda AS SELECT source_local || '@' || source_domain AS \"fqda\" FROM aliases;" | PGPASSWORD=$pgadmpass psql -U "postgres" -h 127.0.0.1 -d "mail_server"
echo "CREATE VIEW view_shared_mailboxes AS SELECT shared_mailbox_local || '@' || shared_mailbox_domain AS \"shared_mailbox\", shared_to_local || '@' || shared_to_domain AS \"shared_to\", 1 AS \"dummy\" FROM shared_mailboxes;" | PGPASSWORD=$pgadmpass psql -U "postgres" -h 127.0.0.1 -d "mail_server"
echo "CREATE VIEW view_public_mailboxes AS SELECT NULL as \"public_mailbox\", NULL as \"dummy\" LIMIT 0;" | PGPASSWORD=$pgadmpass psql -U "postgres" -h 127.0.0.1 -d "mail_server"

echo "CREATE RULE view_shared_mailboxes_insert AS ON INSERT TO view_shared_mailboxes DO INSTEAD INSERT INTO shared_mailboxes (shared_mailbox_local, shared_mailbox_domain, shared_to_local, shared_to_domain) VALUES (split_part(NEW.shared_mailbox,'@',1), split_part(NEW.shared_mailbox,'@',2), split_part(NEW.shared_to,'@',1), split_part(NEW.shared_to,'@',2));" | PGPASSWORD=$pgadmpass psql -U "postgres" -h 127.0.0.1 -d "mail_server"
echo "CREATE RULE view_shared_mailboxes_delete AS ON DELETE TO view_shared_mailboxes DO INSTEAD DELETE FROM shared_mailboxes WHERE shared_mailbox_local = split_part(OLD.shared_mailbox,'@',1) AND shared_mailbox_domain = split_part(OLD.shared_mailbox,'@',2) AND shared_to_local = split_part(OLD.shared_to,'@',1) AND shared_to_domain = split_part(OLD.shared_to,'@',2);" | PGPASSWORD=$pgadmpass psql -U "postgres" -h 127.0.0.1 -d "mail_server"

echo "CREATE ROLE mail_user WITH LOGIN ENCRYPTED PASSWORD '$pgmailuserpass';" | PGPASSWORD=$pgadmpass psql -U "postgres" -h 127.0.0.1 -d "mail_server"
echo "GRANT CONNECT ON DATABASE mail_server TO mail_user;" | PGPASSWORD=$pgadmpass psql -U "postgres" -h 127.0.0.1 -d "mail_server"
echo "GRANT SELECT ON domains, users, aliases, users_fqda, aliases_fqda, view_shared_mailboxes, view_public_mailboxes TO mail_user;" | PGPASSWORD=$pgadmpass psql -U "postgres" -h 127.0.0.1 -d "mail_server"
echo "GRANT INSERT, DELETE ON view_shared_mailboxes TO mail_user;" | PGPASSWORD=$pgadmpass psql -U "postgres" -h 127.0.0.1 -d "mail_server"

echo "INSERT INTO domains (domain) VALUES ('$mydomain');" | PGPASSWORD=$pgadmpass psql -U "postgres" -h 127.0.0.1 -d "mail_server"

####################################
############# POSTFIX ##############

rm -f /etc/postfix/pgsql-virtual-mailbox-domains.cf
rm -f /etc/postfix/pgsql-virtual-mailbox-maps.cf
rm -f /etc/postfix/pgsql-virtual-alias-maps.cf

touch /etc/postfix/pgsql-virtual-mailbox-domains.cf /etc/postfix/pgsql-virtual-mailbox-maps.cf /etc/postfix/pgsql-virtual-alias-maps.cf
chgrp postfix /etc/postfix/pgsql-*.cf
chmod 640 /etc/postfix/pgsql-*.cf

echo "user = mail_user" >> /etc/postfix/pgsql-virtual-mailbox-domains.cf
echo "password = $pgmailuserpass" >> /etc/postfix/pgsql-virtual-mailbox-domains.cf
echo "hosts = 127.0.0.1" >> /etc/postfix/pgsql-virtual-mailbox-domains.cf
echo "dbname = mail_server" >> /etc/postfix/pgsql-virtual-mailbox-domains.cf
echo "query = SELECT * FROM domains WHERE domain='%s'" >> /etc/postfix/pgsql-virtual-mailbox-domains.cf

echo "user = mail_user" >> /etc/postfix/pgsql-virtual-mailbox-maps.cf
echo "password = $pgmailuserpass" >> /etc/postfix/pgsql-virtual-mailbox-maps.cf
echo "hosts = 127.0.0.1" >> /etc/postfix/pgsql-virtual-mailbox-maps.cf
echo "dbname = mail_server" >> /etc/postfix/pgsql-virtual-mailbox-maps.cf
echo "query = SELECT fqda FROM users_fqda WHERE fqda='%s';" >> /etc/postfix/pgsql-virtual-mailbox-maps.cf

echo "user = mail_user" >> /etc/postfix/pgsql-virtual-alias-maps.cf
echo "password = $pgmailuserpass" >> /etc/postfix/pgsql-virtual-alias-maps.cf
echo "hosts = 127.0.0.1" >> /etc/postfix/pgsql-virtual-alias-maps.cf
echo "dbname = mail_server" >> /etc/postfix/pgsql-virtual-alias-maps.cf
echo "query = SELECT destination_local || '@' || destination_domain FROM aliases WHERE source_local='%u' AND source_domain='%d';" >> /etc/postfix/pgsql-virtual-alias-maps.cf

rm -f /etc/postfix/main.cf

echo "# Postfix config" >> /etc/postfix/main.cf
echo "myhostname = $myhostname.$mydomain" >> /etc/postfix/main.cf
echo "mydestination = \$myhostname, $myhostname.$mydomain, localhost.$mydomain, , localhost" >> /etc/postfix/main.cf
echo "smtpd_banner = \$myhostname ESMTP \$mail_name" >> /etc/postfix/main.cf
echo "biff = no" >> /etc/postfix/main.cf
echo "append_dot_mydomain = no" >> /etc/postfix/main.cf
echo "readme_directory = no" >> /etc/postfix/main.cf
echo "compatibility_level = 2" >> /etc/postfix/main.cf
echo "smtpd_tls_cert_file=/etc/letsencrypt/live/$myhostname.$mydomain/fullchain.pem" >> /etc/postfix/main.cf
echo "smtpd_tls_key_file=/etc/letsencrypt/live/$myhostname.$mydomain/privkey.pem" >> /etc/postfix/main.cf
echo "smtpd_use_tls=yes" >> /etc/postfix/main.cf
echo "smtpd_tls_security_level=may" >> /etc/postfix/main.cf
echo "smtpd_tls_auth_only=yes" >> /etc/postfix/main.cf
echo "smtp_tls_security_level=may" >> /etc/postfix/main.cf
echo "smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1, !TLSv1.2" >> /etc/postfix/main.cf
echo "tls_preempt_cipherlist = yes" >> /etc/postfix/main.cf
echo "tls_ssl_options = NO_RENEGOTIATION" >> /etc/postfix/main.cf
echo "smtpd_tls_session_cache_database = btree:\${data_directory}/smtpd_scache" >> /etc/postfix/main.cf
echo "smtp_tls_session_cache_database = btree:\${data_directory}/smtp_scache" >> /etc/postfix/main.cf
echo "smtpd_sasl_type=dovecot" >> /etc/postfix/main.cf
echo "smtpd_sasl_path=private/auth" >> /etc/postfix/main.cf
echo "smtpd_sasl_auth_enable=yes" >> /etc/postfix/main.cf
echo "virtual_mailbox_domains=pgsql:/etc/postfix/pgsql-virtual-mailbox-domains.cf" >> /etc/postfix/main.cf
echo "virtual_mailbox_maps=pgsql:/etc/postfix/pgsql-virtual-mailbox-maps.cf" >> /etc/postfix/main.cf
echo "virtual_alias_maps=pgsql:/etc/postfix/pgsql-virtual-alias-maps.cf" >> /etc/postfix/main.cf
echo "virtual_transport=lmtp:unix:private/dovecot-lmtp" >> /etc/postfix/main.cf
echo "smtpd_client_restrictions = permit_mynetworks permit_sasl_authenticated reject_unknown_reverse_client_hostname" >> /etc/postfix/main.cf
echo "smtpd_helo_restrictions = permit_mynetworks permit_sasl_authenticated reject_invalid_helo_hostname reject_non_fqdn_helo_hostname reject_unknown_helo_hostname" >> /etc/postfix/main.cf
echo "smtpd_helo_required=yes" >> /etc/postfix/main.cf
echo "smtpd_sender_login_maps = pgsql:/etc/postfix/pgsql-virtual-mailbox-maps.cf pgsql:/etc/postfix/pgsql-virtual-alias-maps.cf" >> /etc/postfix/main.cf
echo "smtpd_sender_restrictions = reject_non_fqdn_sender reject_sender_login_mismatch reject_unknown_sender_domain" >> /etc/postfix/main.cf
echo "smtpd_relay_restrictions = permit_sasl_authenticated reject_unauth_destination" >> /etc/postfix/main.cf
echo "smtpd_recipient_restrictions = reject_non_fqdn_recipient reject_unknown_recipient_domain reject_unauth_pipelining" >> /etc/postfix/main.cf
echo "message_size_limit=52428800" >> /etc/postfix/main.cf
echo "smtpd_milters=inet:127.0.0.1:11332" >> /etc/postfix/main.cf
echo "non_smtpd_milters=inet:127.0.0.1:11332" >> /etc/postfix/main.cf
echo "milter_mail_macros=i {mail_addr} {client_addr} {client_name} {auth_authen}" >> /etc/postfix/main.cf
echo "alias_maps = hash:/etc/aliases" >> /etc/postfix/main.cf
echo "alias_database = hash:/etc/aliases" >> /etc/postfix/main.cf
echo "myorigin = /etc/mailname" >> /etc/postfix/main.cf
echo "relayhost = " >> /etc/postfix/main.cf
echo "mynetworks = 127.0.0.0/8" >> /etc/postfix/main.cf
echo "mailbox_size_limit = 0" >> /etc/postfix/main.cf
echo "recipient_delimiter = +" >> /etc/postfix/main.cf
echo "inet_interfaces = all" >> /etc/postfix/main.cf
echo "inet_protocols = all" >> /etc/postfix/main.cf
echo "mime_header_checks = regexp:/etc/postfix/submission_header_cleanup.cf" >> /etc/postfix/main.cf
echo "header_checks = regexp:/etc/postfix/submission_header_cleanup.cf" >> /etc/postfix/main.cf

# Header cleanup file
rm -f /etc/postfix/submission_header_cleanup.cf
echo "/^Received:/ IGNORE" >> /etc/postfix/submission_header_cleanup.cf
echo "/^User-Agent:/ IGNORE" >> /etc/postfix/submission_header_cleanup.cf
echo "/^X-Mailer:/ IGNORE" >> /etc/postfix/submission_header_cleanup.cf
echo "/^X-Originating-IP:/ IGNORE" >> /etc/postfix/submission_header_cleanup.cf
echo "/^X-PHP-Originating-Script/ IGNORE" >> /etc/postfix/submission_header_cleanup.cf
echo "/^Mime-Version:/ IGNORE" >> /etc/postfix/submission_header_cleanup.cf

postmap /etc/postfix/submission_header_cleanup.cf

# Create folder for mails
groupadd --gid 5000 vmail
useradd --gid vmail --uid 5000 --home /var/vmail --create-home --shell /usr/sbin/nologin vmail
chmod o= /var/vmail

#rspamd
rm -f /etc/rspamd/override.d/milter_headers.conf
echo "extended_spam_headers = true;" >> /etc/rspamd/override.d/milter_headers.conf

#DKIM
mkdir --mode=770 /var/lib/rspamd/dkim
chown _rspamd:_rspamd /var/lib/rspamd/dkim

rm -f /etc/rspamd/local.d/dkim_signing.conf

echo "path = \"/var/lib/rspamd/dkim/\$domain.\$selector.key\";" >> /etc/rspamd/local.d/dkim_signing.conf
echo "selector_map = \"/etc/rspamd/dkim_selectors.map\";" >>/etc/rspamd/local.d/dkim_signing.conf

rm -f /etc/rspamd/dkim_selectors.map
echo "$mydomain "


#############################################
################# DOVECOT ###################

rm -f /etc/dovecot/conf.d/10-ssl.conf

echo "ssl = required" >> /etc/dovecot/conf.d/10-ssl.conf
echo "ssl_cert = </etc/letsencrypt/live/$myhostname.$mydomain/fullchain.pem" >> /etc/dovecot/conf.d/10-ssl.conf
echo "ssl_key = </etc/letsencrypt/live/$myhostname.$mydomain/privkey.pem" >> /etc/dovecot/conf.d/10-ssl.conf
echo "ssl_min_protocol = TLSv1.2" >> /etc/dovecot/conf.d/10-ssl.conf
echo "ssl_client_ca_dir = /etc/ssl/certs" >> /etc/dovecot/conf.d/10-ssl.conf
echo "ssl_dh = </usr/share/dovecot/dh.pem" >> /etc/dovecot/conf.d/10-ssl.conf

rm -f /etc/dovecot/conf.d/10-auth.conf

echo "auth_mechanisms = plain" >> /etc/dovecot/conf.d/10-auth.conf
echo "!include auth-sql.conf.ext" >> /etc/dovecot/conf.d/10-auth.conf

rm -f /etc/dovecot/conf.d/auth-sql.conf.ext

echo "passdb {" >> /etc/dovecot/conf.d/auth-sql.conf.ext
echo "  driver = sql" >> /etc/dovecot/conf.d/auth-sql.conf.ext
echo "  args = /etc/dovecot/dovecot-sql.conf.ext" >> /etc/dovecot/conf.d/auth-sql.conf.ext
echo "}" >> /etc/dovecot/conf.d/auth-sql.conf.ext
echo "userdb {" >> /etc/dovecot/conf.d/auth-sql.conf.ext
echo "  driver = static" >> /etc/dovecot/conf.d/auth-sql.conf.ext
echo "  args = uid=vmail gid=vmail home=/var/vmail/%d/%n" >> /etc/dovecot/conf.d/auth-sql.conf.ext
echo "}" >> /etc/dovecot/conf.d/auth-sql.conf.ext

rm -f /etc/dovecot/dovecot-sql.conf.ext

echo "driver = pgsql" >> /etc/dovecot/dovecot-sql.conf.ext
echo "connect = host=127.0.0.1 dbname=mail_server port=5432 user=mail_user password=$pgmailuserpass" >> /etc/dovecot/dovecot-sql.conf.ext
echo "default_pass_scheme = ARGON2ID" >> /etc/dovecot/dovecot-sql.conf.ext
echo "password_query = SELECT fqda AS user, password_hash AS password FROM users_fqda WHERE fqda='%u';" >> /etc/dovecot/dovecot-sql.conf.ext

rm -f /etc/dovecot/conf.d/10-mail.conf

echo "mail_location = maildir:~/Maildir" >> /etc/dovecot/conf.d/10-mail.conf
echo "namespace inbox {" >> /etc/dovecot/conf.d/10-mail.conf
echo "  type = private" >> /etc/dovecot/conf.d/10-mail.conf
echo "  separator = /" >> /etc/dovecot/conf.d/10-mail.conf
echo "  prefix =" >> /etc/dovecot/conf.d/10-mail.conf
echo "  inbox = yes" >> /etc/dovecot/conf.d/10-mail.conf
echo "}" >> /etc/dovecot/conf.d/10-mail.conf
echo "namespace {" >> /etc/dovecot/conf.d/10-mail.conf
echo "  type = shared" >> /etc/dovecot/conf.d/10-mail.conf
echo "  separator = /" >> /etc/dovecot/conf.d/10-mail.conf
echo "  prefix = shared/%%u/" >> /etc/dovecot/conf.d/10-mail.conf
echo "  location = maildir:%%h/Maildir:INDEXPVT=~/Maildir/shared/%%u" >> /etc/dovecot/conf.d/10-mail.conf
echo "  subscriptions = no" >> /etc/dovecot/conf.d/10-mail.conf
echo "  list = children" >> /etc/dovecot/conf.d/10-mail.conf
echo "}" >> /etc/dovecot/conf.d/10-mail.conf
echo "mail_plugins = acl" >> /etc/dovecot/conf.d/10-mail.conf
echo "mail_privileged_group = mail" >> /etc/dovecot/conf.d/10-mail.conf
echo "protocol !indexer-worker {" >> /etc/dovecot/conf.d/10-mail.conf
echo "}" >> /etc/dovecot/conf.d/10-mail.conf

rm -f /etc/dovecot/conf.d/15-mailboxes.conf

echo "namespace inbox {" >> /etc/dovecot/conf.d/15-mailboxes.conf
echo "  mailbox Inbox {" >> /etc/dovecot/conf.d/15-mailboxes.conf
echo "    auto = subscribe" >> /etc/dovecot/conf.d/15-mailboxes.conf
echo "  }" >> /etc/dovecot/conf.d/15-mailboxes.conf
echo "  mailbox Drafts {" >> /etc/dovecot/conf.d/15-mailboxes.conf
echo "    auto = subscribe" >> /etc/dovecot/conf.d/15-mailboxes.conf
echo "    special_use = \Drafts" >> /etc/dovecot/conf.d/15-mailboxes.conf
echo "  }" >> /etc/dovecot/conf.d/15-mailboxes.conf
echo "  mailbox Junk {" >> /etc/dovecot/conf.d/15-mailboxes.conf
echo "    auto = subscribe" >> /etc/dovecot/conf.d/15-mailboxes.conf
echo "    special_use = \Junk" >> /etc/dovecot/conf.d/15-mailboxes.conf
echo "  }" >> /etc/dovecot/conf.d/15-mailboxes.conf
echo "  mailbox Trash {" >> /etc/dovecot/conf.d/15-mailboxes.conf
echo "    auto = subscribe" >> /etc/dovecot/conf.d/15-mailboxes.conf
echo "    special_use = \Trash" >> /etc/dovecot/conf.d/15-mailboxes.conf
echo "  }" >> /etc/dovecot/conf.d/15-mailboxes.conf
echo "  mailbox Sent {" >> /etc/dovecot/conf.d/15-mailboxes.conf
echo "    auto = subscribe" >> /etc/dovecot/conf.d/15-mailboxes.conf
echo "    special_use = \Sent" >> /etc/dovecot/conf.d/15-mailboxes.conf
echo "  }" >> /etc/dovecot/conf.d/15-mailboxes.conf
echo "  mailbox \"Sent Messages\" {" >> /etc/dovecot/conf.d/15-mailboxes.conf
echo "    special_use = \Sent" >> /etc/dovecot/conf.d/15-mailboxes.conf
echo "  }" >> /etc/dovecot/conf.d/15-mailboxes.conf
echo "}" >> /etc/dovecot/conf.d/15-mailboxes.conf

rm -f /etc/dovecot/conf.d/10-master.conf

echo "service imap-login {" >> /etc/dovecot/conf.d/10-master.conf
echo "  inet_listener imap {" >> /etc/dovecot/conf.d/10-master.conf
echo "  }" >> /etc/dovecot/conf.d/10-master.conf
echo "  inet_listener imaps {" >> /etc/dovecot/conf.d/10-master.conf
echo "  }" >> /etc/dovecot/conf.d/10-master.conf
echo "  process_min_avail = 1" >> /etc/dovecot/conf.d/10-master.conf
echo "}" >> /etc/dovecot/conf.d/10-master.conf
echo "service pop3-login {" >> /etc/dovecot/conf.d/10-master.conf
echo "  inet_listener pop3 {" >> /etc/dovecot/conf.d/10-master.conf
echo "  }" >> /etc/dovecot/conf.d/10-master.conf
echo "  inet_listener pop3s {" >> /etc/dovecot/conf.d/10-master.conf
echo "  }" >> /etc/dovecot/conf.d/10-master.conf
echo "}" >> /etc/dovecot/conf.d/10-master.conf
echo "service submission-login {" >> /etc/dovecot/conf.d/10-master.conf
echo "  inet_listener submission {" >> /etc/dovecot/conf.d/10-master.conf
echo "  }" >> /etc/dovecot/conf.d/10-master.conf
echo "}" >> /etc/dovecot/conf.d/10-master.conf
echo "service lmtp {" >> /etc/dovecot/conf.d/10-master.conf
echo "  unix_listener /var/spool/postfix/private/dovecot-lmtp {" >> /etc/dovecot/conf.d/10-master.conf
echo "    user = postfix" >> /etc/dovecot/conf.d/10-master.conf
echo "    group = postfix" >> /etc/dovecot/conf.d/10-master.conf
echo "    mode = 0600" >> /etc/dovecot/conf.d/10-master.conf
echo "  } " >> /etc/dovecot/conf.d/10-master.conf
echo "}" >> /etc/dovecot/conf.d/10-master.conf
echo "service imap {" >> /etc/dovecot/conf.d/10-master.conf
echo "}" >> /etc/dovecot/conf.d/10-master.conf
echo "service pop3 {" >> /etc/dovecot/conf.d/10-master.conf
echo "}" >> /etc/dovecot/conf.d/10-master.conf
echo "service submission {" >> /etc/dovecot/conf.d/10-master.conf
echo "}" >> /etc/dovecot/conf.d/10-master.conf
echo "service auth {" >> /etc/dovecot/conf.d/10-master.conf
echo "  unix_listener /var/spool/postfix/private/auth {" >> /etc/dovecot/conf.d/10-master.conf
echo "    user = postfix" >> /etc/dovecot/conf.d/10-master.conf
echo "    group = postfix" >> /etc/dovecot/conf.d/10-master.conf
echo "    mode = 0660" >> /etc/dovecot/conf.d/10-master.conf
echo "  }" >> /etc/dovecot/conf.d/10-master.conf
echo "}" >> /etc/dovecot/conf.d/10-master.conf
echo "service auth-worker {" >> /etc/dovecot/conf.d/10-master.conf
echo "}" >> /etc/dovecot/conf.d/10-master.conf
echo "service dict {" >> /etc/dovecot/conf.d/10-master.conf
echo "  unix_listener dict {" >> /etc/dovecot/conf.d/10-master.conf
echo "  mode = 0600" >> /etc/dovecot/conf.d/10-master.conf
echo "  user = vmail" >> /etc/dovecot/conf.d/10-master.conf
echo "  }" >> /etc/dovecot/conf.d/10-master.conf
echo "}" >> /etc/dovecot/conf.d/10-master.conf

rm -f /etc/dovecot/conf.d/20-lmtp.conf

echo "protocol lmtp {" >> /etc/dovecot/conf.d/20-lmtp.conf
echo "  mail_plugins = \$mail_plugins sieve" >> /etc/dovecot/conf.d/20-lmtp.conf
echo "}" >> /etc/dovecot/conf.d/20-lmtp.conf

rm -f /etc/dovecot/conf.d/20-imap.conf

echo "protocol imap {" >> /etc/dovecot/conf.d/20-imap.conf
echo "  mail_plugins = \$mail_plugins imap_acl" >> /etc/dovecot/conf.d/20-imap.conf
echo "  mail_max_userip_connections = 50" >> /etc/dovecot/conf.d/20-imap.conf
echo "}" >> /etc/dovecot/conf.d/20-imap.conf

rm -f /etc/dovecot/conf.d/90-acl.conf

echo "plugin {" >> /etc/dovecot/conf.d/90-acl.conf
echo "  acl = vfile" >> /etc/dovecot/conf.d/90-acl.conf
echo "}" >> /etc/dovecot/conf.d/90-acl.conf
echo "plugin {" >> /etc/dovecot/conf.d/90-acl.conf
echo "  acl_shared_dict = proxy::acl" >> /etc/dovecot/conf.d/90-acl.conf
echo "}" >> /etc/dovecot/conf.d/90-acl.conf

rm -f /etc/dovecot/dovecot.conf

echo "dict {" >> /etc/dovecot/dovecot.conf
echo "  acl = pgsql:/etc/dovecot/dovecot-dict-sql.conf.ext" >> /etc/dovecot/dovecot.conf
echo "}" >> /etc/dovecot/dovecot.conf
echo "!include_try /usr/share/dovecot/protocols.d/*.protocol" >> /etc/dovecot/dovecot.conf
echo "!include conf.d/*.conf" >> /etc/dovecot/dovecot.conf
echo "!include_try local.conf" >> /etc/dovecot/dovecot.conf

rm -f /etc/dovecot/dovecot-dict-sql.conf.ext

echo "connect = host=127.0.0.1 dbname=mail_server port=5432 user=mail_user password=$pgmailuserpass" >> /etc/dovecot/dovecot-dict-sql.conf.ext
echo "map {" >> /etc/dovecot/dovecot-dict-sql.conf.ext
echo "  pattern = shared/shared-boxes/user/\$to/\$from" >> /etc/dovecot/dovecot-dict-sql.conf.ext
echo "  table = view_shared_mailboxes" >> /etc/dovecot/dovecot-dict-sql.conf.ext
echo "  value_field = dummy" >> /etc/dovecot/dovecot-dict-sql.conf.ext
echo "  fields {" >> /etc/dovecot/dovecot-dict-sql.conf.ext
echo "    shared_mailbox = \$from" >> /etc/dovecot/dovecot-dict-sql.conf.ext
echo "    shared_to = \$to" >> /etc/dovecot/dovecot-dict-sql.conf.ext
echo "  }" >> /etc/dovecot/dovecot-dict-sql.conf.ext
echo "}" >> /etc/dovecot/dovecot-dict-sql.conf.ext
echo "map {" >> /etc/dovecot/dovecot-dict-sql.conf.ext
echo "  pattern = shared/shared-boxes/anyone/\$from" >> /etc/dovecot/dovecot-dict-sql.conf.ext
echo "  table = view_public_mailboxes" >> /etc/dovecot/dovecot-dict-sql.conf.ext
echo "  value_field = dummy" >> /etc/dovecot/dovecot-dict-sql.conf.ext
echo "  fields {" >> /etc/dovecot/dovecot-dict-sql.conf.ext
echo "    public_mailbox = \$from" >> /etc/dovecot/dovecot-dict-sql.conf.ext
echo "  }" >> /etc/dovecot/dovecot-dict-sql.conf.ext
echo "}" >> /etc/dovecot/dovecot-dict-sql.conf.ext

mkdir /etc/dovecot/sieve-before

rm -f /etc/dovecot/conf.d/90-sieve.conf

echo "plugin {" >> /etc/dovecot/conf.d/90-sieve.conf
echo "  sieve = file:~/sieve;active=~/.dovecot.sieve" >> /etc/dovecot/conf.d/90-sieve.conf
echo "  sieve_before = /etc/dovecot/sieve-before" >> /etc/dovecot/conf.d/90-sieve.conf
echo "}" >> /etc/dovecot/conf.d/90-sieve.conf

rm -f /etc/dovecot/sieve-before/spam-to-junk.sieve

echo "require \"fileinto\";" >> /etc/dovecot/sieve-before/spam-to-junk.sieve
echo "if header :contains \"X-Spam\" \"Yes\" {" >> /etc/dovecot/sieve-before/spam-to-junk.sieve
echo " fileinto \"Junk\";" >> /etc/dovecot/sieve-before/spam-to-junk.sieve
echo " stop;" >> /etc/dovecot/sieve-before/spam-to-junk.sieve
echo "}" >> /etc/dovecot/sieve-before/spam-to-junk.sieve

sievec /etc/dovecot/sieve-before/spam-to-junk.sieve


echo "Please generate SSL certs and DKIM manyally, check master.cf file and after that start Postfix, Dovecot, Apache2."
echo "postgres password is $pgadmpass Save in a secure place!"  
echo "Bye!"
echo
