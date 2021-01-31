#!/bin/bash
pgadmpass="PASSWORD"

echo "Mailbox user creation script"
# Read Password
echo -n "Mailbox Username:"
read -r usrname
if [ -z "$usrname" ]; then
    echo "Username can not be empty!"
    echo "Bye!"
    exit
fi
echo -n "Mailbox Domain (example.com):"
read -r dmnname
if [ -z "$dmnname" ]; then
    echo "Domain name can not be empty!"
    echo "Bye!"
    exit
fi
echo -n "Password:" 
read -s password1
echo
echo -n "Repeat password:"
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
  echo "insert into users values (:'dmnname', :'usrname', :'pass')" | PGPASSWORD=$pgadmpass psql -U "postgres" -d "mail_server" -h 127.0.0.1 -v pass="$hss" -v dmnname="$dmnname" -v usrname="$usrname"
  echo "Mailbox user created."
  echo "Bye!"
else
  echo "ERROR: Wrong password!"
fi
