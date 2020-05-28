# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-55973" do
  title "The web server must use a logging mechanism that is configured to
alert the ISSO and SA in the event of a processing failure."
  desc  "Reviewing log data allows an investigator to recreate the path of an
attacker and to capture forensic data for later use. Log data is also essential
to system administrators in their daily administrative duties on the hosted
system or within the hosted applications.

    If the logging system begins to fail, events will not be recorded.
Organizations shall define logging failure events, at which time the
application or the logging mechanism the application utilizes will provide a
warning to the ISSO and SA at a minimum.
  "
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and deployment configuration settings
to determine if the web server logging system provides an alert to the ISSO and
the SA at a minimum when a processing failure occurs.

    If alerts are not sent or the web server is not configured to use a
dedicated logging tool that meets this requirement, this is a finding.
  "
  desc  "fix", "
    Configure the web server to provide an alert to the ISSO and SA when log
processing failures occur.

    If the web server cannot generate alerts, utilize an external logging
system that meets this criterion.
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000108-WSR-000166"
  tag "gid": "V-55973"
  tag "rid": "SV-70227r2_rule"
  tag "stig_id": "SRG-APP-000108-WSR-000166"
  tag "fix_id": "F-60851r2_fix"
  tag "cci": ["CCI-000139"]
  tag "nist": ["AU-5 a", "Rev_4"]


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

