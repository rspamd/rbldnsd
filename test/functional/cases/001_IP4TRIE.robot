*** Settings ***
Test Teardown   Rbldnsd Teardown
Library         ${RBLDNSD_TESTDIR}/lib/rbldnsd.py
Resource        ${RBLDNSD_TESTDIR}/lib/rbldnsd.robot
Variables       ${RBLDNSD_TESTDIR}/lib/vars.py

*** Test Cases ***
TEST EXCLUSION
  [Setup]  Zone Setup  ip4trie  1.2.3.0/24 listed\n!1.2.3.4
  ${q1} =  Reversed IP4  1.2.3.4
  Query Rbldnsd  ${q1}
  Expect No Query Result

  ${q2} =  Reversed IP4  1.2.3.3
  Query Rbldnsd  ${q2}
  Expect Query Result  listed

  ${q3} =  Reversed IP4  1.2.3.5
  Query Rbldnsd  ${q3}
  Expect Query Result  listed

TEST WILDCARD PREFIX
  [Setup]  Zone Setup  ip4trie  0/0 wild\n127.0.0.1 localhost
  ${q1} =  Reversed IP4  127.0.0.1
  Query Rbldnsd  ${q1}
  Expect Query Result  localhost

  ${q2} =  Reversed IP4  0.0.0.0
  Query Rbldnsd  ${q2}
  Expect Query Result  wild

  ${q3} =  Reversed IP4  127.0.0.2
  Query Rbldnsd  ${q3}
  Expect Query Result  wild
