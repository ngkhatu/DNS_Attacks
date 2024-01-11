#!/bin/sh

# script created for CIS644 Lab 4, Kevin - Mar 18, 2013

# the payload_answer2 is a special raw data file that carefully constructured
# to use this file, you should insert two byte as Transaction ID at position 0 of the file
# then read 11 bytes, insert your random domain name at position 13(2+11)
# then append the fake DNS server IP address in the end of the file

./pacgen2
