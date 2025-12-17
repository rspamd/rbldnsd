local architectures = ['X64', 'ARM64'];

local imagemap = {
  'centos-8': 'almalinux:8',
  'centos-9': 'almalinux:9',
  'centos-10': 'almalinux:10',
  'debian-bullseye': 'debian:bullseye',
  'debian-bookworm': 'debian:bookworm',
  'debian-trixie': 'debian:trixie',
  'ubuntu-jammy': 'ubuntu:22.04',
  'ubuntu-noble': 'ubuntu:24.04',
};

local distribs_deb = [
  key
  for key in std.objectFields(imagemap)
  if std.startsWith(key, 'debian-') || std.startsWith(key, 'ubuntu-')
];

local distribs_rpm = [
  key
  for key in std.objectFields(imagemap)
  if std.startsWith(key, 'centos-')
];

local build_test_pipeline = {
  name: 'build_test',
  on: {
    workflow_call: {
      inputs: {
        version: {
          required: true,
          type: 'string',
        },
        experimental: {
          required: false,
          type: 'boolean',
        },
        branch: {
          required: false,
          type: 'string',
          default: 'master',
        },
        repo: {
          required: false,
          type: 'string',
          default: 'rspamd/rbldnsd',
        },
        distributions: {
          required: false,
          type: 'string',
          description: 'Comma-separated list (e.g., ubuntu-jammy,debian-bookworm). Empty = all.',
        },
        architectures: {
          required: false,
          type: 'string',
          description: 'Comma-separated list (e.g., X64,ARM64). Empty = all.',
        },
      },
    },
  },
};

// Check if a distribution should be built
// If distributions is empty, build all. Otherwise check if name is in the comma-separated list.
// We wrap with commas so "centos-10" doesn't match "centos-101"
local include_distro(name) =
  'inputs.distributions == \'\' || contains(format(\',{0},\', inputs.distributions), format(\',{0},\', \'' + name + '\'))';

// Check if an architecture should be built
// If architectures is empty, build all. Otherwise check if arch is in the comma-separated list.
local include_arch(arch) =
  'inputs.architectures == \'\' || contains(format(\',{0},\', inputs.architectures), format(\',{0},\', \'' + arch + '\'))';

local build_test_jobs(name, image) = {
  local build_with(arch) = {
    name: name,
    platform: arch,
    version: '${{ inputs.version }}',
    experimental: '${{ inputs.experimental }}',
    branch: '${{ inputs.branch }}',
    repo: '${{ inputs.repo }}',
  },
  [name + '-build-' + arch]: {
    'if': '${{ (' + include_distro(name) + ') && (' + include_arch(arch) + ') }}',
    uses: './.github/workflows/build_packages.yml',
    with: build_with(arch),
  }
  for arch in architectures
} + {
  local test_with(arch) = {
    name: name,
    image: image,
    platform: arch,
    revision: '${{ needs.' + name + '-build-' + arch + '.outputs.revision }}',
  },
  [name + '-test-' + arch]: {
    'if': '${{ (' + include_distro(name) + ') && (' + include_arch(arch) + ') && !(vars.SKIP_TESTS || vars.SKIP_TESTS_' + std.asciiUpper(std.strReplace(name, '-', '_')) + ') }}',
    needs: name + '-build-' + arch,
    uses: './.github/workflows/test_package.yml',
    with: test_with(arch),
  }
  for arch in architectures
};

local build_jobs_list = [
  build_test_jobs(p.key, p.value)
  for p in std.objectKeysValues(imagemap)
];

local all_jobs = {
  jobs:
    std.foldl(std.mergePatch, build_jobs_list, {})
};

{
  'build_test.yml': build_test_pipeline + all_jobs,
}
