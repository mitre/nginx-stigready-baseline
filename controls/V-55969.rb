control 'V-55969' do
  title "The NGINX web server must not impede the ability to write specified log
record content to an audit log server."
  desc  "Writing events to a centralized management audit system offers many
benefits to the enterprise over having dispersed logs. Centralized management
of audit records and logs provides for efficiency in maintenance and management
of records, enterprise analysis of events, and backup and archiving of event
records enterprise-wide. The web server and related components are required to
be capable of writing logs to centralized audit log servers."

  desc  'check', "Review the NGINX web server documentation and deployment configuration to
  determine if the web server can write log data to, or if log data can be
  transferred to, a separate audit server.

  If there are no websites configured for NGINX, this check is Not Applicable.

  Check for the following:
      # grep for 'access_log' and 'error_log' directives in the nginx.conf and
      any separated include configuration file.

  If the 'access_log' and 'error_log' directives cannot be found in NGINX configuration
  files, this check is Not Applicable.

  Execute the following commands:
      # file <path to access_log>/access.log
      # file <path to error_log>/error.log

  If the access.log and error.log files do not exist, this is a finding.

  Work with SIEM administrator to determine audit configurations.

  If there is a setting within the SIEM that could impede the ability to write
  specific log record content, this is a finding.
  "
  desc 'fix', "Enable logging on the NGINX web server by configuring the 'access_log'
  and 'error_log' directives in the NGINX configuration file(s).

  Work with the SIEM administrator to allow the ability to write specified log record
  content to an audit log server."
  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'SRG-APP-000358-WSR-000063'
  tag "gid": 'V-55969'
  tag "rid": 'SV-70223r2_rule'
  tag "stig_id": 'SRG-APP-000358-WSR-000063'
  tag "fix_id": 'F-60847r1_fix'
  tag "cci": ['CCI-001851']
  tag "nist": ['AU-4 (1)', 'Rev_4']

  # Verify that access_log and error_log is enabled
  if nginx_conf.params['http'].nil?
    impact 0.0
    describe 'This check is NA because no websites have been configured.' do
      skip 'This check is NA because no websites have been configured.'
    end
  else
    nginx_conf.params['http'].each do |http|
      if http['access_log'].nil?
        impact 0.0
        describe 'This test is NA because the access_log directive has not been configured.' do
          skip 'This test is NA because access_log directive has not been configured.'
        end
      else
        http['access_log'].each do |access_log|
          access_log.each do |access_value|
            next unless access_value.include? 'access.log'
            describe file(access_value) do
              it 'The access log should exist.' do
                expect(subject).to(exist)
              end
            end
          end
        end
      end
    end
    if nginx_conf.params['error_log'].nil?
      impact 0.0
      describe 'This test is NA because the error_log directive has not been configured.' do
        skip 'This test is NA because error_log directive has not been configured.'
      end
    else
      nginx_conf.params['error_log'].each do |error_log|
        error_log.each do |error_value|
          next unless error_value.include? 'error.log'
          describe file(error_value) do
            it 'The error log should exist.' do
              expect(subject).to(exist)
            end
          end
        end
      end
    end
    describe "This test requires a Manual Review: Work with SIEM administrator
    to determine audit configurations to ensure the ability to write specified
    log record content to an audit log server." do
      skip "This test requires a Manual Review: Work with SIEM administrator
      to determine audit configurations to ensure the ability to write specified
      log record content to an audit log server."
    end
  end
end
