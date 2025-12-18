*** Settings ***
Test Teardown   Rbldnsd Teardown
Library         ${RBLDNSD_TESTDIR}/lib/rbldnsd.py
Resource        ${RBLDNSD_TESTDIR}/lib/rbldnsd.robot
Variables       ${RBLDNSD_TESTDIR}/lib/vars.py

*** Test Cases ***
TEST DNHASH PLAIN MATCH
  [Setup]  Zone Setup  dnhash  listed.tld LISTED
  ${q1} =  Set Variable  listed.tld.${SOA}
  Query Rbldnsd  ${q1}
  Expect Query Status  NOERROR
  Expect Query Result  LISTED

TEST DNHASH WILDCARDS AND EXCLUSIONS
  [Setup]  Zone Setup  dnhash  *.wild.tld WILD\n.wild2.tld WILD2\n!excluded.wild2.tld

  # "*.wild.tld" matches subdomains only
  ${q1} =  Set Variable  x.wild.tld.${SOA}
  Query Rbldnsd  ${q1}
  Expect Query Result  WILD

  ${q2} =  Set Variable  wild.tld.${SOA}
  Query Rbldnsd  ${q2}
  Expect No Query Result

  # ".wild2.tld" matches both the name itself and all subdomains
  ${q3} =  Set Variable  wild2.tld.${SOA}
  Query Rbldnsd  ${q3}
  Expect Query Result  WILD2

  ${q4} =  Set Variable  x.wild2.tld.${SOA}
  Query Rbldnsd  ${q4}
  Expect Query Result  WILD2

  # Exclusion should override the wildcarded inclusion
  ${q5} =  Set Variable  excluded.wild2.tld.${SOA}
  Query Rbldnsd  ${q5}
  Expect No Query Result
