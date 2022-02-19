control 'V-55993' do
  title "Anonymous user access to the NGINX web server application directories must
be prohibited."
  desc  "In order to properly monitor the changes to the web server and the
hosted applications, logging must be enabled. Along with logging being enabled,
each record must properly contain the changes made and the names of those who
made the changes.

    Allowing anonymous users the capability to change the web server or the
hosted application will not generate proper log information that can then be
used for forensic reporting in the case of a security issue. Allowing anonymous
users to make changes will also grant change capabilities to anybody without
forcing a user to authenticate before the changes can be made.
  "

  desc 'check', "Review the NGINX web server documentation and configuration
  to determine if anonymous users can make changes to the web server or any
  applications hosted by the web server.

  Obtain a list of the user accounts for the system, noting the privileges for each account.

  Verify with the System Administrator (SA) or the Information System Security Officer (ISSO) that
  all privileged accounts are mission essential and documented.

  Verify with the SA or the ISSO that all non-administrator access to shell scripts and operating
  system functions are mission essential and documented.

  If there are no valid login shells, this check is Not Applicable.

  If undocumented privileged accounts are present, this is a finding.

  If undocumented access to shell scripts or operating system functions is present (i.e. anonymous users
  can make changes), this is a finding.
  "
  desc 'fix', "Ensure non-administrators (e.g. anonymous) are not allowed access to the directory tree,
  the shell, or other operating system functions and utilities."
  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'SRG-APP-000211-WSR-000031'
  tag "gid": 'V-55993'
  tag "rid": 'SV-70247r2_rule'
  tag "stig_id": 'SRG-APP-000211-WSR-000031'
  tag "fix_id": 'F-60871r1_fix'
  tag "cci": ['CCI-001082']
  tag "nist": %w(SC-2 Rev_4)

  valid_login_shells = command("grep '^[^#]' /etc/shells").stdout.split("\n")

  if valid_login_shells.empty?
    impact 0.0
    describe 'This check is NA because the there are no valid login shells.' do
      skip 'This check is NA because the there are no valid login shells.'
    end
  else
    valid_login_shells.each do |shell|
      describe 'Unauthorized users' do
        it 'should not have shell access.' do
          expect(users.shells(/#{shell}/).usernames).to(be_in(input('sys_admin').clone << input('nginx_owner')))
        end
      end
    end
  end
end
