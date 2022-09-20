control 'V-55987' do
  title "The account used to run the NGINX web server must not have a valid
  login shell and password defined."
  desc  "During installation of the web server software, accounts are created
for the web server to operate properly. The accounts installed can have either
no password installed or a default password, which will be known and documented
by the vendor and the user community.

    The first things an attacker will try when presented with a login screen
are the default user identifiers with default passwords. Installed applications
may also install accounts with no password, making the login even easier. Once
the web server is installed, the passwords for any created accounts should be
changed and documented. The new passwords must meet the requirements for all
passwords, i.e., upper/lower characters, numbers, special characters, time
until change, reuse policy, etc.

    Service accounts or system accounts that have no login capability do not
need to have passwords set or changed.
  "

  desc 'check', "Review the NGINX web server documentation and deployment
  configuration to determine what non-service/system accounts were installed
  by the web server installation process.

  Identify the account that is running the 'nginx' process:
    # ps -ef | grep -i nginx | grep -v grep

  root       675     1  0 Jun01 ?        00:00:00 nginx: master process /usr/sbin/nginx -c /etc/nginx/nginx.conf
  nginx      677   675  0 Jun01 ?        00:00:00 nginx: worker process

  If no service accounts are found, this check is Not Applicable.

  Check to see if the accounts have a valid login shell:

    # cut -d: -f1,7 /etc/passwd | grep -i nginx:/sbin/nologin
    # cut -d: -f1,7 /etc/passwd | grep -i root:/sbin/nologin

  If the service account has a valid login shell, verify that no password is
  configured for the account:

    # cut -d: -f1,2 /etc/shadow | grep -i root:!
    # cut -d: -f1,2 /etc/shadow | grep -i nginx:!

  If the account has a valid login shell and a password defined,
  this is a finding.
  "
  desc 'fix', "
  Update the /etc/passwd file to assign the accounts used to run the 'nginx'
  process an invalid login shell such as '/sbin/nologin'.

  Lock the accounts used to run the 'nginx' process:

  # passwd -l
  Locking password for user
  passwd: Success
  "
  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'SRG-APP-000516-WSR-000079'
  tag "gid": 'V-55987'
  tag "rid": 'SV-70241r2_rule'
  tag "stig_id": 'SRG-APP-000516-WSR-000079'
  tag "fix_id": 'F-60865r1_fix'
  tag "cci": ['CCI-000366']
  tag "nist": ['CM-6 b', '']

  service_accounts = []

  if command('ps').exist?
    ps_output = command('ps -ef | grep -i nginx | grep -v grep').stdout.split("\n")

    ps_output.each do |output|
      account = command("echo '#{output}' | awk '{print $1}'").stdout.split
      service_accounts.push(account)
    end
  else
    service_accounts = input('sys_admin').clone << input('nginx_owner')
  end

  if service_accounts.empty?
    impact 0.0
    describe 'This test is NA because the no service accounts were found.' do
      skip 'This test is NA because the service accounts were found.'
    end
  else
    service_accounts.flatten.uniq
    service_accounts.each do |account|
      describe.one do
        describe command("cut -d: -f1,7 /etc/passwd | grep -i #{account}") do
          its('stdout') { should match %r{/sbin/nologin} }
        end
        describe command("cut -d: -f1,7 /etc/passwd | grep -i #{account}") do
          its('stdout') { should match %r{/bin/false} }
        end
      end
      describe.one do
        describe command("cut -d: -f1,2 /etc/shadow | grep -i '#{account}'") do
          its('stdout') { should match "#{account}:!" }
        end

        describe command("cut -d: -f1,2 /etc/shadow | grep -i '#{account}'") do
          its('stdout') { should match "#{account}:\\*" }
        end
      end
    end
  end
end
