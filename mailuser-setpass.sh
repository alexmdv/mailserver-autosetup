#!/bin/bash
pgadmpass="PASSWORD"

echo "Mailbox password update script."
# Read Password
echo -n "Mailbox Username:"
read -r usrname
if [ -z "$usrname" ]; then
    echo "Username can not be empty!"
    echo "Bye!"
    exit
fi
echo -n "Mailbox domain (example.com):"
read -r dmnname
if [ -z "$dmnname" ]; then
    echo "Domain name can not be empty!"
    echo "Bye!"
    exit
fi
echo -n "New password:" 
read -s password1
echo
echo -n "Repeat new password:"
read -s password2
echo
if [[ "$password1" == "$password2" ]]; then
  if [ -z "$password1" ]; then
    echo "Password can not be empty!"
    echo "Bye!"
    exit
  fi
  mysalt=$(pwgen 16 1)
  hss=$(echo -n $password1 | argon2 $mysalt -id -e)
  echo "UPDATE users SET password_hash=:'pass' WHERE local=:'usrname' and domain=:'dmnname'" | PGPASSWORD=$pgadmpass psql -U "postgres" -d "mail_server" -h 127.0.0.1 -v pass="$hss" -v usrname="$usrname" -v dmnname="$dmnname"
  echo "Mailbox password updated."
  echo "Bye!"
else
  echo "ERROR: Wrong password!"
fi
