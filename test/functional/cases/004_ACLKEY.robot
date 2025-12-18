*** Settings ***
Test Teardown   Rbldnsd Teardown
Library         ${RBLDNSD_TESTDIR}/lib/rbldnsd.py
Resource        ${RBLDNSD_TESTDIR}/lib/rbldnsd.robot
Variables       ${RBLDNSD_TESTDIR}/lib/vars.py

*** Keywords ***
ACLKEY Setup
  [Arguments]  ${aclkey}
  Prepare Temporary Directory
  Create File  ${RBLDNSD_TMPDIR}/aclkey  ${DUMMY_ZONE_HEADER}${aclkey}
  Create File  ${RBLDNSD_TMPDIR}/generic  ${DUMMY_ZONE_HEADER}test TXT "Success"
  @{RBLDNSD_ZONES} =  Create List
  ...  ${SOA}:generic:${RBLDNSD_TMPDIR}/generic
  ...  ${SOA}:aclkey:${RBLDNSD_TMPDIR}/aclkey
  Set Test Variable  ${RBLDNSD_ZONES}
  Run Rbldnsd

*** Test Cases ***
TEST ACLKEY REFUSE WITHOUT KEY
  [Setup]  ACLKEY Setup  :refuse\nsecret :pass
  Query Rbldnsd  test.${SOA}
  Expect Query Status  REFUSED

TEST ACLKEY PASS WITH KEY
  [Setup]  ACLKEY Setup  :refuse\nsecret :pass
  Query Rbldnsd  test.secret.${SOA}
  Expect Query Status  NOERROR
  Expect Query Result  Success

TEST ACLKEY REFUSE UNKNOWN KEY
  [Setup]  ACLKEY Setup  :refuse\nsecret :pass
  Query Rbldnsd  test.unknown.${SOA}
  Expect Query Status  REFUSED
