#!/bin/sh

SLAPD=/usr/libexec/slapd
SLAPADD=/usr/sbin/slapadd
MKDIR=mkdir
RM=rm
KILL=kill

$RM -rf openldap-data
$MKDIR openldap-data

$SLAPADD -f slapd.conf < startup.ldif
$SLAPD -d 4 -F . -f ./slapd.conf -hldap://localhost:1234 

# slapd should be running now

#node test3.js

# kill slapd
#$KILL -15 `cat slapd.pid`
