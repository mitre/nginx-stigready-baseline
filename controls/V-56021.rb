control 'V-56021' do
  title "The NGINX web server must invalidate session identifiers upon hosted
  application user logout or other session termination."
  desc "Captured sessions can be reused in \"replay\" attacks. This
  requirement limits the ability of adversaries from capturing and continuing to
  employ previously valid session IDs.

    Session IDs are tokens generated by web applications to uniquely identify
  an application user's session. Unique session IDs help to reduce predictability
  of said identifiers. When a user logs out, or when any other session
  termination event occurs, the web server must terminate the user session to
  minimize the potential for an attacker to hijack that particular user session.
  "

  desc 'check', "Review the web server documentation and deployed configuration
  to verify that the web server is configured to invalidate session identifiers when a
  session is terminated.

  If it is determined that the web server is not required to perform session
  management, this check is Not Applicable.

  If the web server does not invalidate session identifiers when a session is
  terminated, this is a finding.
  "
  desc 'fix', "Configure the web server to invalidate session identifiers when
  a session is terminated."
  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'SRG-APP-000220-WSR-000201'
  tag "gid": 'V-56021'
  tag "rid": 'SV-70275r2_rule'
  tag "stig_id": 'SRG-APP-000220-WSR-000201'
  tag "fix_id": 'F-60899r1_fix'
  tag "cci": ['CCI-001185']
  tag "nist": ['SC-23 (1)', '']

  if input('performs_session_management') == false
    impact 0.0
    describe 'This check is NA because session management is not required.' do
      skip 'This check is NA because session management is not required.'
    end
  else
    describe "This test requires a Manual Review: Verify it invalidates session identifiers when a
    session is terminated by reviewing the NGINX documentation." do
      skip "This test requires a Manual Review: Verify it invalidates session identifiers when a
      session is terminated by reviewing the NGINX documentation."
    end
  end
end
