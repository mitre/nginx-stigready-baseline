# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-41674" do
  title "The log data and records from the web server must be backed up onto a
different system or media."
  desc  "Protection of log data includes assuring log data is not accidentally
lost or deleted. Backing up log records to an unrelated system or onto separate
media than the system the web server is actually running on helps to assure
that, in the event of a catastrophic system failure, the log records will be
retained."
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and deployed configuration to determine
if the web server log records are backed up onto an unrelated system or media
than the system being logged.

    If the web server logs are not backed up onto a different system or media
than the system being logged, this is a finding.
  "
  desc  "fix", "Configure the web server logs to be backed up onto a different
system or media other than the system being logged."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000125-WSR-000071"
  tag "gid": "V-41674"
  tag "rid": "SV-54251r3_rule"
  tag "stig_id": "SRG-APP-000125-WSR-000071"
  tag "fix_id": "F-47133r3_fix"
  tag "cci": ["CCI-001348"]
  tag "nist": ["AU-9 (2)", "Rev_4"]

  # Ensure access log is linked to stdout
  describe command('readlink ' + access_log_path) do
    its('stdout') { should eq "/dev/stdout\n" }
    # its('stdout') { should cmp '/proc/1/fd/pipe' }
  end
  # Ensure error log is linked to stderror
  describe command('readlink ' + error_log_path)do
    its('stdout') { should eq "/dev/stderr\n" }
    # its('stdout') { should cmp '/proc/1/fd/pipe' }
  end
  
end

