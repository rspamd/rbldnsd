*** Settings ***
Test Teardown   Rbldnsd Teardown
Library         ${RBLDNSD_TESTDIR}/lib/rbldnsd.py
Resource        ${RBLDNSD_TESTDIR}/lib/rbldnsd.robot
Variables       ${RBLDNSD_TESTDIR}/lib/vars.py

*** Keywords ***
ACL Setup
  [Arguments]  ${acl}
  Prepare Temporary Directory
  Create File  ${RBLDNSD_TMPDIR}/acl  ${DUMMY_ZONE_HEADER}${acl}
  Create File  ${RBLDNSD_TMPDIR}/generic  ${DUMMY_ZONE_HEADER}test TXT "Success"
  @{RBLDNSD_ZONES} =  Create List
  ...  ${SOA}:generic:${RBLDNSD_TMPDIR}/generic
  ...  ${SOA}:acl:${RBLDNSD_TMPDIR}/acl
  Set Test Variable  ${RBLDNSD_ZONES}
  Run Rbldnsd

*** Test Cases ***
TEST ACL REFUSE IP4
  [Setup]  ACL Setup  127.0.0.1 :refuse
  Query Rbldnsd  test.example.com  v6=False
  Expect Query Status  REFUSED

TEST ACL ALLOW IP4
  [Setup]  ACL Setup  0.0.0.0/0 :refuse\n127.0.0.1 :pass
  Query Rbldnsd  test.example.com  v6=False
  Expect Query Status  NOERROR

TEST ACL REFUSE IP6
  [Setup]  ACL Setup  ::1 :refuse
  IF  not ${RBLDNSD_HASV6}
    Skip
  END
  Query Rbldnsd  test.example.com  v6=True
  Expect Query Status  REFUSED

TEST ACL ALLOW IP6
  [Setup]  ACL Setup  0/0 :refuse\n0::1 :pass
  IF  not ${RBLDNSD_HASV6}
    Skip
  END
  Query Rbldnsd  test.example.com  v6=True
  Expect Query Status  NOERROR
