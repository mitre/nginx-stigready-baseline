control 'V-55955' do
  title "The NGINX web server must provide the capability to immediately disconnect
or disable remote access to the hosted applications."
  desc  "During an attack on the web server or any of the hosted applications,
the system administrator may need to disconnect or disable access by users to
stop the attack.

    The web server must provide a capability to disconnect users to a hosted
application without compromising other hosted applications unless deemed
necessary to stop the attack. Methods to disconnect or disable connections are
to stop the application service for a specified hosted application, stop the
web server, or block all connections through web server access list.

    The web server capabilities used to disconnect or disable users from
connecting to hosted applications and the web server must be documented to make
certain that, during an attack, the proper action is taken to conserve
connectivity to any other hosted application if possible and to make certain
log data is conserved for later forensic analysis.
  "

  desc 'check', "Review the NGINX web server documentation and configuration
  to make certain that the web server is configured to allow for the immediate
  disconnection or disabling of remote access to hosted applications when necessary.

  Interview the SA and Web Manager.

  Ask for documentation for the NGINX administration.

  Verify there are documented procedures for shutting down an NGINX website in the
  event of an attack. The procedure should, at a minimum, provide the following steps:

  Determine the respective website for the application at risk of an attack.

  In a command line, enter the following command:

  # kill -TERM `cat <'INSTALLED PATH'>/nginx.pid`

  If NGINX is not capable of or cannot be configured to disconnect or disable remote
  access to the hosted applications when necessary, this is a finding.
  "
  desc  'fix', "Prepare documented procedures for shutting down an NGINX website in the
  event of an attack.

  The procedure should, at a minimum, provide the following steps:

  In a command line, enter the following command:

    # kill -TERM `cat <'INSTALLED PATH'>/nginx.pid`"
  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'SRG-APP-000316-WSR-000170'
  tag "gid": 'V-55955'
  tag "rid": 'SV-70209r2_rule'
  tag "stig_id": 'SRG-APP-000316-WSR-000170'
  tag "fix_id": 'F-60833r1_fix'
  tag "cci": ['CCI-002322']
  tag "nist": ['AC-17 (9)', '']

  describe "This test requires a Manual Review: Interview the SA and Web Manager and ask
  for documentation.Verify there are documented procedures for shutting down an NGINX website
  in the event of an attack." do
    skip "This test requires a Manual Review: Interview the SA and Web Manager and ask
    for documentation.Verify there are documented procedures for shutting down an NGINX website
    in the event of an attack."
  end
end
