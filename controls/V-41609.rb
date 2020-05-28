# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-41609" do
  title "The web server must capture, record, and log all content related to a
user session."
  desc  "A user session to a web server is in the context of a user accessing a
hosted application that extends to any plug-ins/modules and services that may
execute on behalf of the user.

    The web server must be capable of enabling a setting for troubleshooting,
debugging, or forensic gathering purposes which will log all user session
information related to the hosted application session. Without the capability
to capture, record, and log all content related to a user session,
investigations into suspicious user activity would be hampered.
  "
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and deployed configuration to determine
if the web server captures and logs all content related to a user session.

    Request a user access the hosted applications and verify the complete
session is logged.

    If any of the session is excluded from the log, this is a finding.
  "
  desc  "fix", "Configure the web server to capture and log all content related
to a user session."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000093-WSR-000053"
  tag "gid": "V-41609"
  tag "rid": "SV-54186r3_rule"
  tag "stig_id": "SRG-APP-000093-WSR-000053"
  tag "fix_id": "F-47068r2_fix"
  tag "cci": ["CCI-001462"]
  tag "nist": ["AU-14 (2)", "Rev_4"]

  # log_format - Context:	http
  Array(nginx_conf(conf_path).params['http']).each do |http|
    Array(http["log_format"]).each do |log_format|
      describe 'remote_user' do
        # it { should match /.*?\$remote_user.*?/ }
        it 'should be part of every log format in the http context.' do
          expect(log_format.to_s).to(match /.*?\$remote_user.*?/)
        end
      end
    end
  end  
end

