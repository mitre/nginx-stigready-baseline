# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-55969" do
  title "The web server must not impede the ability to write specified log
record content to an audit log server."
  desc  "Writing events to a centralized management audit system offers many
benefits to the enterprise over having dispersed logs. Centralized management
of audit records and logs provides for efficiency in maintenance and management
of records, enterprise analysis of events, and backup and archiving of event
records enterprise-wide. The web server and related components are required to
be capable of writing logs to centralized audit log servers."
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and deployment configuration to
determine if the web server can write log data to, or if log data can be
transferred to, a separate audit server.

    Request a user access the hosted application and generate logable events
and verify the data is written to a separate audit server.

    If logs cannot be directly written or transferred on request or on a
periodic schedule to an audit log server, this is a finding.
  "
  desc  "fix", "Configure the web server to directly write or transfer the logs
to a remote audit log server."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000358-WSR-000063"
  tag "gid": "V-55969"
  tag "rid": "SV-70223r2_rule"
  tag "stig_id": "SRG-APP-000358-WSR-000063"
  tag "fix_id": "F-60847r1_fix"
  tag "cci": ["CCI-001851"]
  tag "nist": ["AU-4 (1)", "Rev_4"]

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

