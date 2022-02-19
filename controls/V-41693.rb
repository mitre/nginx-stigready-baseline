control 'V-41693' do
  title "The NGINX web server must only contain services and functions necessary for
  operation."
  desc "A web server can provide many features, services, and processes. Some
  of these may be deemed unnecessary or too unsecure to run on a production DoD
  system.

    The web server must provide the capability to disable, uninstall, or
  deactivate functionality and services that are deemed to be non-essential to
  the web server mission or can adversely impact server performance.
  "

  desc 'check', "Review the NGINX web server documentation and deployed configuration
  to determine if web server features, services, and processes are installed that are not
  needed for hosted application deployment.

  If the site requires the use of a particular piece of software, the ISSO will need
  to maintain documentation identifying this software as necessary for operations. The
  software must be operated at the vendor’s current patch level and must be a supported
  vendor release.

  If programs or utilities that meet the above criteria are installed on the Web Server,
  and appropriate documentation and signatures are in evidence, this is not a finding.

  Determine whether the web server is configured with unnecessary software.

  Determine whether processes other than those that support the web server are loaded
  and/or run on the web server.

  Examples of software that should not be on the web server are all web development
  tools, office suites (unless the web server is a private web development server),
  compilers, and other utilities that are not part of the web server suite or the basic
  operating system.

  Check the directory structure of the server and ensure that additional, unintended, or
  unneeded applications are not loaded on the system.

  If, after review of the application on the system, there is no justification for the
  identified software, this is a finding.
  "
  desc 'fix', "Uninstall or deactivate features, services, and processes not
needed by the NGINX web server for operation."
  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'SRG-APP-000141-WSR-000075'
  tag "gid": 'V-41693'
  tag "rid": 'SV-54270r3_rule'
  tag "stig_id": 'SRG-APP-000141-WSR-000075'
  tag "fix_id": 'F-47152r2_fix'
  tag "cci": ['CCI-000381']
  tag "nist": ['CM-7 a', 'Rev_4']

  describe "This test requires a Manual Review: Check the directory structure of the server and
  ensure that additional, unintended, or unneeded applications are not loaded on the system." do
    skip "This test requires a Manual Review: Check the directory structure of the server and
  ensure that additional, unintended, or unneeded applications are not loaded on the system."
  end
end
