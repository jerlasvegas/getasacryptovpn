#!/usr/bin/python3

from ciscoasa import ciscoASA
import re
from pprint import PrettyPrinter

def main():

  pp = PrettyPrinter()

  src_fw = '1.1.1.1'
  user = 'user'
  passwd = 'password'

  crypto_dict = {}
  crypto_acl_regex = '^crypto\smap\s\S*\s(\d{1,3})\smatch\saddress\s(\S*)'
  crypto_peer_regex = '^crypto\smap\s\S*\s(\d{1,3})\sset\speer\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
  gp_regex = '^\s*default-group-policy\s(\S*)'
  vfilter_regex = '^\s*vpn-filter\svalue\s(\S*)'
  acl_regex = '.*(ip|udp|tcp)\s(any|host\s\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s(any|host\s\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s(eq)?\s?(\d{1,5})?'
  
  with ciscoASA(src_fw,user,passwd) as con:
    crypto_peers = con.getCryptoPeer()
    for peer in crypto_peers:
      crypto_acl_pattern = re.match(crypto_acl_regex,peer,re.VERBOSE)
      crypto_peer_pattern = re.match(crypto_peer_regex,peer,re.VERBOSE)
      if crypto_acl_pattern:
        my_peer = crypto_acl_pattern.group(1)
        my_acl = crypto_acl_pattern.group(2)
        crypto_dict[my_peer] = {'acl': my_acl}
        acl = con.getACL(my_acl)
        crypto_dict[my_peer]['vpn_traffic'] = []
        for entry in acl:
          acl_pat = re.match(acl_regex,entry)
          if acl_pat:
            crypto_dict[my_peer]['vpn_traffic'].append((acl_pat.group(2),acl_pat.group(3)))
      if crypto_peer_pattern:
        if my_peer == crypto_peer_pattern.group(1):
          my_peer_ip = crypto_peer_pattern.group(2)
          crypto_dict[my_peer]['peer'] = my_peer_ip
          tunnel_group = con.getTunnelGroup(my_peer_ip)
          for tuncfg in tunnel_group:
            gp_pattern = re.match(gp_regex,tuncfg,re.VERBOSE)
            if gp_pattern:
              my_gp = gp_pattern.group(1)
              crypto_dict[my_peer]['gp'] = my_gp
              group_policy = con.getGroupPolicy(my_gp)
              for grpcfg in group_policy:
                vfilter_pattern = re.match(vfilter_regex,grpcfg,re.VERBOSE)
                if vfilter_pattern:
                  vfilter_acl = vfilter_pattern.group(1)
                  crypto_dict[my_peer]['vfilter'] = vfilter_acl
                  facl = con.getACL(vfilter_acl)
                  crypto_dict[my_peer]['vpn_filter'] = []
                  for entry in facl:
                    facl_pat = re.match(acl_regex,entry)
                    if facl_pat:
                      if facl_pat.group(5):
                        crypto_dict[my_peer]['vpn_filter'].append({'protocol': facl_pat.group(1),
                                                                   'destination': facl_pat.group(2),
                                                                   'source': facl_pat.group(3),
                                                                   'port': facl_pat.group(5)})
                      else:
                        crypto_dict[my_peer]['vpn_filter'].append({'protocol': facl_pat.group(1),
                                                                   'destination': facl_pat.group(2),
                                                                   'source': facl_pat.group(3)})

  pp.pprint(crypto_dict)

if __name__ == "__main__":
    main()
