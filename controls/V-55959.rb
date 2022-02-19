control 'V-55959' do
  title "The NGINX web server must use a logging mechanism that is configured to
allocate log record storage capacity large enough to accommodate the logging
requirements of the web server."
  desc  "In order to make certain that the logging mechanism used by the web
server has sufficient storage capacity in which to write the logs, the logging
mechanism needs to be able to allocate log record storage capacity.

    The task of allocating log record storage capacity is usually performed
during initial installation of the logging mechanism. The system administrator
will usually coordinate the allocation of physical drive space with the web
server administrator along with the physical location of the partition and
disk. Refer to NIST SP 800-92 for specific requirements on log rotation and
storage dependent on the impact of the web server.
  "

  desc 'check', "Review the NGINX web server documentation and deployment configuration to
  determine if the web server is using a logging mechanism to store log records.
  If a logging mechanism is in use, validate that the mechanism is configured to
  use record storage capacity in accordance with specifications within NIST SP
  800-92 for log record storage requirements.

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

  Work with SIEM administrator to determine log storage capacity.
  If there is no setting within a SIEM to accommodate enough a large logging
  capacity, this is a finding.
  "
  desc 'fix', "Enable logging on the NGINX web server by configuring the 'access_log'
  and 'error_log' directives in the NGINX configuration file(s).

  Work with the SIEM administrator to determine if the SIEM is configured to allocate
  log record storage capacity large enough to accommodate the logging requirements of
  the NGINX web server."

  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'SRG-APP-000357-WSR-000150'
  tag "gid": 'V-55959'
  tag "rid": 'SV-70213r2_rule'
  tag "stig_id": 'SRG-APP-000357-WSR-000150'
  tag "fix_id": 'F-60837r1_fix'
  tag "cci": ['CCI-001849']
  tag "nist": %w(AU-4 Rev_4)

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
    minimum_size = input('minimum_log_file_size')
    describe "This test requires a Manual Review: Work with SIEM administrator
    to determine log storage capacity. The minimum capacity should equal
    #{minimum_size}." do
      skip "This test requires a Manual Review: Work with SIEM administrator
      to determine log storage capacity. The minimum capacity should equal
      #{minimum_size}."
    end
  end
end
