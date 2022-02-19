control 'V-41670' do
  title 'Web NGINX server log files must only be accessible by privileged users.'
  desc  "Log data is essential in the investigation of events. If log data were
  to become compromised, then competent forensic analysis and discovery of the
  true source of potentially malicious system activity would be difficult, if not
  impossible, to achieve. In addition, access to log records provides information
  an attacker could potentially use to their advantage since each event record
  might contain communication ports, protocols, services, trust relationships,
  user names, etc.

      The web server must protect the log data from unauthorized read, write,
  copy, etc. This can be done by the web server if the web server is also doing
  the logging function. The web server may also use an external log system. In
  either case, the logs must be protected from access by non-privileged users.
  "
  desc 'check', "
  Review the NGINX web server documentation and deployed configuration settings to
  determine if the web server logging features protect log information from
  unauthorized access.

  Check for the following:
      # grep for 'access_log' and 'error_log' directives in the nginx.conf
      and any separated include configuration file.

  Execute the following commands:
      # ls -alH <nginx log directory>
      # ls -alH <path to access_log>/access.log
      # ls -alH <path to error_log>/error.log

  Note the owner and group permissions on these files. Only system administrators
  and service accounts running the server should have permissions to the directory and files.
     - The SA or service account should own the directory and files
     - Permissions on the directory should be 750 or more restrictive
     - Permissions on these files should be 640 or more restrictive

  If any users other than those authorized have read access to the log files, this
  is a finding.
  "
  desc 'fix', "To protect the integrity of the data that is being captured in the
  log files, ensure that only the members of the Auditors group, Administrators,
  and the user assigned to run the web server software is granted permissions to
  read the log files."

  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'SRG-APP-000118-WSR-000068'
  tag "gid": 'V-41670'
  tag "rid": 'SV-54247r3_rule'
  tag "stig_id": 'SRG-APP-000118-WSR-000068'
  tag "fix_id": 'F-47129r2_fix'
  tag "cci": ['CCI-000162']
  tag "nist": %w(AU-9 Rev_4)

  # nginx log directory should have 750 permissions
  describe file(input('nginx_log_path')) do
    its('owner') { should be_in input('sys_admin').clone << input('nginx_owner') }
    its('group') { should be_in input('sys_admin_group').clone << input('nginx_group') }
    it { should_not be_more_permissive_than('0750') }
  end

  # log file in docker are symlinks
  if virtualization.system.eql?('docker')
    # nginx access log file should have 660 permissions
    describe file(input('access_log_path')) do
      its('owner') { should be_in input('sys_admin').clone << input('nginx_owner') }
      its('group') { should be_in input('sys_admin_group').clone << input('nginx_group') }
    end

    # nginx error log file should have 660 permissions
    describe file(input('error_log_path')) do
      its('owner') { should be_in input('sys_admin').clone << input('nginx_owner') }
      its('group') { should be_in input('sys_admin_group').clone << input('nginx_group') }
    end
  else
    # nginx access log file should have 660 permissions
    describe file(input('access_log_path')) do
      its('owner') { should be_in input('sys_admin').clone << input('nginx_owner') }
      its('group') { should be_in input('sys_admin_group').clone << input('nginx_group') }
      it { should_not be_more_permissive_than('0640') }
    end

    # nginx error log file should have 660 permissions
    describe file(input('error_log_path')) do
      its('owner') { should be_in input('sys_admin').clone << input('nginx_owner') }
      its('group') { should be_in input('sys_admin_group').clone << input('nginx_group') }
      it { should_not be_more_permissive_than('0640') }
    end
  end
end
