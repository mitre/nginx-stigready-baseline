control 'V-55961' do
  title 'The NGINX web server must restrict inbound connections from nonsecure zones.'
  desc  "Remote access to the web server is any access that communicates
through an external, non-organization-controlled network. Remote access can be
used to access hosted applications or to perform management functions.

    A web server can be accessed remotely and must be capable of restricting
access from what the DoD defines as nonsecure zones. Nonsecure zones are
defined as any IP, subnet, or region that is defined as a threat to the
organization. The nonsecure zones must be defined for public web servers
logically located in a DMZ, as well as private web servers with perimeter
protection devices. By restricting access from nonsecure zones, through
internal web server access list, the web server can stop or slow denial of
service (DoS) attacks on the web server.
  "

  desc 'check', "
  Review the NGINX web server configuration to verify that the web server is
  restricting access from nonsecure zones.

  If the an enterprise tools is enforcing the organization's requirements for remote
  connections, this control must be reviewed manually.

  Check for the following:
      # grep for a 'deny' directive in the location context of the nginx.conf
      and any separated include configuration file.

  Verify that there is a 'deny all' set in each location context to deny all IP
  addresses by default and only allow addresses in secure zones. If a 'deny all'
  is not set in each location, this is a finding.
  "
  desc 'fix', "Add a 'deny all' in each location context in the NGINX configuration
  file(s) to deny access to all IP addresses by default, including addresses in
  nonsecure zones.

  Then add 'allow' directive(s) in each location context in the NGINX configuration file(s)
  and configure it to only allow addresses in secure zones."

  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'SRG-APP-000315-WSR-000004'
  tag "gid": 'V-55961'
  tag "rid": 'SV-70215r2_rule'
  tag "stig_id": 'SRG-APP-000315-WSR-000004'
  tag "fix_id": 'F-60839r1_fix'
  tag "cci": ['CCI-002314']
  tag "nist": ['AC-17 (1)', '']

  if input('uses_enterprise_tool') == 'true'
    describe "This test requires a Manual Review: Determine if the enterprise tool is enforcing
    the organization's requirements for remote connections." do
      skip "This test requires a Manual Review: Determine if the enterprise tool is enforcing
      the organization's requirements for remote connections."
    end
  elsif nginx_conf.locations.empty?
    impact 0.0
    describe 'This check is NA because NGINX has not been configured to serve files.' do
      skip 'This check is NA because NGINX has not been configured to serve files.'
    end
  else
    nginx_conf.locations.each do |location|
      deny_values = []
      deny_values.push(location.params['deny']) unless location.params['deny'].nil?
      describe 'Each location context' do
        it 'should include an deny all directive.' do
          expect(deny_values.to_s).to(include 'all')
        end
      end
    end
  end
end
