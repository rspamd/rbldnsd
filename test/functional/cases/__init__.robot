*** Settings ***
Suite Setup     Export Global Variables
Library         Process
Library         ../lib/rbldnsd.py
Variables       ../lib/vars.py

*** Keywords ***
Export Global Variables
  ${RBLDNSD_TESTDIR} =  Get Test Directory
  ${TOPDIR} =  Get Top Dir

  ${RBLDNSD_BIN} =  Replace Variables  ${RBLDNSD_BIN}

  Set Global Variable  ${RBLDNSD_BIN}
  Set Global Variable  ${RBLDNSD_TESTDIR}
  Set Global Variable  ${TOPDIR}

  ${result} =  Run Process  ${RBLDNSD_BIN}  -h
  ${contains6} =  Evaluate  """\n -6""" in """${result.stdout}"""
  IF  ${contains6}
    Set Global Variable  ${RBLDNSD_HASV6}  True
  ELSE
    Set Global Variable  ${RBLDNSD_HASV6}  False
  END
