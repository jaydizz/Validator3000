# Validator3000 - A Ris-Live Route Validation Tool 

Validator3000 is a toolkit that collects routing announcements from ris-live and validates them against different IRRs and RPKI-TALs. 
It consists of two seperate tools:

## Luke DB-Walker

Parses IRR-Databses in RPSL for route-objects and generates a Patricia Trie. The Trie's nodes hold a data-hashref, that includes all validation data. 

## Ris-live
Connects to the ris-live websocket, validates announcements and writes the results to an influx-db. 

# Dependencies

NOTE: the Local Libraries used will be published later on! 
NOTE: All tool functionality will be eventually moved to a cpan module!

