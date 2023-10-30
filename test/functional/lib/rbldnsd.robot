*** Settings ***
Library         Collections
Library         OperatingSystem
Library         Process

*** Keywords ***
Expect No Query Result
  Expect Query Result  ${NONE}

Expect Query Result
  [Arguments]  ${expected_result}
  Should Be Equal As Strings  ${QUERY_RESULT}  ${expected_result}


Expect Query Status
  [Arguments]  ${expected_status}
  Should Be Equal  ${QUERY_STATUS}  ${expected_status}


Export Scoped Variables
  [Arguments]  ${scope}  &{vars}
  IF  '${scope}' == 'Test'
    FOR  ${k}  ${v}  IN  &{vars}
      Set Test Variable  ${${k}}  ${v}
    END
  ELSE IF  '${scope}' == 'Suite'
    FOR  ${k}  ${v}  IN  &{vars}
      Set Suite Variable  ${${k}}  ${v}
    END
  ELSE IF  '${scope}' == 'Global'
    FOR  ${k}  ${v}  IN  &{vars}
      Set Global Variable  ${${k}}  ${v}
    END
  ELSE
    Fail  message="Don't know what to do with scope: ${scope}"
  END


Prepare Temporary Directory
  ${RBLDNSD_TMPDIR} =  Make Temporary Directory
  Export Scoped Variables  ${RBLDNSD_SCOPE}
  ...  RBLDNSD_TMPDIR=${RBLDNSD_TMPDIR}


Query Rbldnsd
  [Arguments]  ${name}  ${type}=TXT  ${v6}=False
  IF  ${v6}
    ${address} =  Set Variable  ::1
  ELSE
    ${address} =  Set Variable  127.0.0.1
  END
  ${QUERY_STATUS}  ${QUERY_RESULT} =  Query DNS  ${address}  ${RBLDNSD_PORT}  ${name}  ${type}
  Export Scoped Variables  ${RBLDNSD_SCOPE}
  ...  QUERY_RESULT=${QUERY_RESULT}
  ...  QUERY_STATUS=${QUERY_STATUS}


Rbldnsd Setup
  Prepare Temporary Directory
  Run Rbldnsd


Rbldnsd Teardown
  Terminate Process
  ${result} =  Wait For Process
  ${rbldnsd_stdout} =  Get File  ${RBLDNSD_TMPDIR}/rbldnsd.stdout  encoding_errors=ignore
  ${rbldnsd_stderr} =  Get File  ${RBLDNSD_TMPDIR}/rbldnsd.stderr  encoding_errors=ignore
  IF  '$rbldnsd_stdout' != '$EMPTY'
    Log  ${rbldnsd_stdout}
  END
  IF  'rbldnsd_stderr' != '$EMPTY'
    Log  ${rbldnsd_stderr}
  END
  Remove Directory  ${RBLDNSD_TMPDIR}  recursive=True


Run Rbldnsd
  ${process} =  Start Process  ${RBLDNSD_BIN}
  ...  -b  localhost/${RBLDNSD_PORT}
  ...  -n
  ...  @{RBLDNSD_ZONES}
  ...  stdout=${RBLDNSD_TMPDIR}/rbldnsd.stdout  stderr=${RBLDNSD_TMPDIR}/rbldnsd.stderr
  Wait For Server To Respond


Wait For Server To Respond
  Wait Until Keyword Succeeds  5x  1 sec
  ...  Query Rbldnsd  dummy.nonexisting.zone


Zone Setup
  [Arguments]  ${zone_type}  ${zone_content}
  Prepare Temporary Directory
  Create File  ${RBLDNSD_TMPDIR}/zone  ${DUMMY_ZONE_HEADER}${zone_content}
  @{RBLDNSD_ZONES} =  Create List
  ...  ${SOA}:${zone_type}:${RBLDNSD_TMPDIR}/zone
  Set Test Variable  ${RBLDNSD_ZONES}
  Run Rbldnsd
