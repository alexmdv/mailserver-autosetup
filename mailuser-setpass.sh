#!/bin/bash
pgadmpass="PASSWORD"

echo "Mailbox password update script."
# Read Password
echo -n Mailbox Username:
read -r usrname
echo -n New password: 
read -s password1
echo
echo -n Repeat new password:
read -s password2
echo
mysalt=$(pwgen 16 1)
if [[ "$password1" == "$password2" ]]; then
hss=$(echo -n $password1 | argon2 $mysalt -id -e)
echo "UPDATE users SET password_hash=:'pass' WHERE local=:'usrname'" | PGPASSWORD=$pgadmpass psql -U "postgres" -d "mail_server" -h 127.0.0.1 -v pass="$hss" -v usrname="$usrname"
echo "Mailbox password updated."
echo "Bye!"
else
echo "ERROR: Wrong password!"
fi
