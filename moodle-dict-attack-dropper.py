#!/usr/bin/python
# Detect dictionary attacks against Moodle and drop packets from the perpetrators' IP addresses.
# DEPENDENCY: The 'iptables' executable must be in the search $PATH.

from netfilter.rule import Rule
from netfilter.table import Table
import psycopg2
import re
import config

def db_execute(conn, query, args=None):
    cur = conn.cursor()
    cur.execute(query, args)
    return cur.fetchall()

def get_offending_ips(conn, selectors):
    """Get a list of IPs from the mdl_log table that have more than
       failurelimit authentication failures within the past timewindow seconds"""
    query = """
        SELECT ip
        FROM mdl_log
        WHERE module = 'login'
        AND action = 'error'
        AND time > (EXTRACT (EPOCH FROM NOW()) - %(timewindow)s)
        GROUP BY ip
        HAVING COUNT(*) > %(failurelimit)s
    """
    return db_execute(conn, query, selectors)

def block_ips(ips):
    """For each of the listed source IP addresses (excluding private networks),
       add a netfilter rule to DROP all its packets."""
    # http://stackoverflow.com/questions/2814002/private-ip-address-identifier-in-regular-expression
    private_ips = "^(127|10|172\.1[6-9]|172\.2[0-9]|172\.3[0-1]|192\.168)\."
    for ip, in ips:
        if not re.match(private_ips, ip):
            print "Dropping all packets from %s" % ip
            rule = Rule(source=ip, jump='DROP')
            table = Table('filter')
            table.append_rule('INPUT', rule)
    print "Done processing (blocked %d suspicious IP addresses)" % len(ips)

if __name__=="__main__":
    if (config.selectors["failurelimit"] < 5):
        raise Exception("failurelimit in config.py should be 5 or greater to avoid locking out legitimate users.")
    conn = psycopg2.connect(host = config.db_host, database = config.db_name, user = config.db_username, password = config.db_pw)
    block_ips(get_offending_ips(conn, config.selectors))
