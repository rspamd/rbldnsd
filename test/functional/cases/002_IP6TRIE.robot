*** Settings ***
Test Teardown   Rbldnsd Teardown
Library         ${RBLDNSD_TESTDIR}/lib/rbldnsd.py
Resource        ${RBLDNSD_TESTDIR}/lib/rbldnsd.robot
Variables       ${RBLDNSD_TESTDIR}/lib/vars.py

*** Test Cases ***
TEST EXCLUSION
  [Setup]  Zone Setup  ip6trie  dead::/16 listed\n!dead::beef
  ${q1} =  Reversed IP6  dead::beee
  Query Rbldnsd  ${q1}
  Expect Query Result  listed

  ${q2} =  Reversed IP6  dead::beef
  Query Rbldnsd  ${q2}
  Expect No Query Result
