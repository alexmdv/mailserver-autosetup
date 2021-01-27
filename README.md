# mailserver-autosetup
Script for automatic setup mail server on Debian 10 Buster

Usage:
1. Start mailserver-setup.sh, Specity mail server short hostname, domain name and local IP. When the script finishes copy postgres password and replace with PASSWORD string into mailuser-addnew.sh and mailuser-setpass.sh
2. Replace master.cf in /etc/postfix
3. Generate SSL and DKIM, add DKIM record into /etc/rspamd/dkim_selectors.map
4. Restart the server
5. Use mailuser-addnew.sh for creating new mail user, us mailuser-setpass.sh for changing passwords for existing users.
