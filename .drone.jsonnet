local ci_pipeline(arch) = {
  kind: 'pipeline',
  type: 'docker',
  name: 'default-' + arch,
  platform: {
    os: 'linux',
    arch: arch,
  },
  steps: [
    {
      name: 'test',
      image: 'rspamd/rbldnsd:build',
      commands: [
        'mkdir ../build.rbldnsd',
        'cd ../build.rbldnsd',
        'cmake -DNO_IPv6=ON $DRONE_WORKSPACE',
        'make',
        'cd $DRONE_WORKSPACE',
        'mv ../build.rbldnsd/rbldnsd* .',
        'bash -c "source /venv/bin/activate && robot test/functional/cases"',
        'bash -c "source /venv/bin/activate && python3 test/pyunit/tests.py"',
      ],
    },
  ],
  trigger: {
    event: {
      include: [
        'push',
        'pull_request',
      ],
    },
  },
};
local signature_placeholder = {
  hmac: '0000000000000000000000000000000000000000000000000000000000000000',
  kind: 'signature',
};
[
  ci_pipeline('amd64'),
  ci_pipeline('arm64'),
  signature_placeholder,
]
