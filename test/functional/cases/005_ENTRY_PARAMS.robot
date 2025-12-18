*** Settings ***
Test Teardown   Rbldnsd Teardown
Library         ${RBLDNSD_TESTDIR}/lib/rbldnsd.py
Resource        ${RBLDNSD_TESTDIR}/lib/rbldnsd.robot
Variables       ${RBLDNSD_TESTDIR}/lib/vars.py

*** Keywords ***
Entry Params Setup
  [Arguments]  ${dnhash}  ${aclkey}
  Prepare Temporary Directory
  Create File  ${RBLDNSD_TMPDIR}/dnhash  ${DUMMY_ZONE_HEADER}${dnhash}
  Create File  ${RBLDNSD_TMPDIR}/aclkey  ${DUMMY_ZONE_HEADER}${aclkey}
  @{RBLDNSD_ZONES} =  Create List
  ...  ${SOA}:dnhash:${RBLDNSD_TMPDIR}/dnhash
  ...  ${SOA}:aclkey:${RBLDNSD_TMPDIR}/aclkey
  Set Test Variable  ${RBLDNSD_ZONES}
  Run Rbldnsd

Cooldown Setup
  ${now} =  Evaluate  int(__import__('time').time())
  ${past} =  Evaluate  ${now} - 120
  ${zone} =  Catenate  SEPARATOR=\n
  ...  cooldown.tld COOLDOWN @ ts=${now};delay=60s
  ...  ready.tld READY @ ts=${past};delay=60s
  Entry Params Setup  ${zone}  :pass\nsecret :pass

Key NoDelay Setup
  ${now} =  Evaluate  int(__import__('time').time())
  ${zone} =  Catenate  SEPARATOR=\n
  ...  nodelay.tld NODELAY @ ts=${now};delay=3600s;key=nodelay
  Entry Params Setup  ${zone}  :pass\nsecret :pass

*** Test Cases ***
TEST ENTRY PARAMS COOLDOWN
  [Setup]  Cooldown Setup

  Query Rbldnsd  cooldown.tld.${SOA}
  Expect No Query Result

  Query Rbldnsd  ready.tld.${SOA}
  Expect Query Status  NOERROR
  Expect Query Result  READY

TEST ENTRY PARAMS KEY REQUIRE
  [Setup]  Entry Params Setup
  ...  needkey.tld NEEDKEY @ key=require
  ...  :pass\nsecret :pass

  Query Rbldnsd  needkey.tld.${SOA}
  Expect No Query Result

  Query Rbldnsd  needkey.tld.secret.${SOA}
  Expect Query Status  NOERROR
  Expect Query Result  NEEDKEY

TEST ENTRY PARAMS KEY NODELAY
  [Setup]  Key NoDelay Setup

  Query Rbldnsd  nodelay.tld.${SOA}
  Expect No Query Result

  Query Rbldnsd  nodelay.tld.secret.${SOA}
  Expect Query Status  NOERROR
  Expect Query Result  NODELAY
