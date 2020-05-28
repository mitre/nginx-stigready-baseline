# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-55975" do
  title "The web server must use a logging mechanism that is configured to
provide a warning to the ISSO and SA when allocated record storage volume
reaches 75% of maximum log record storage capacity."
  desc  "It is critical for the appropriate personnel to be aware if a system
is at risk of failing to process logs as required. Log processing failures
include: software/hardware errors, failures in the log capturing mechanisms,
and log storage capacity being reached or exceeded.

    If log capacity were to be exceeded, then events subsequently occurring
would not be recorded. Organizations shall define a maximum allowable
percentage of storage capacity serving as an alarming threshold (e.g., web
server has exceeded 75% of log storage capacity allocated), at which time the
web server or the logging mechanism the web server utilizes will provide a
warning to the ISSO and SA at a minimum.

    This requirement can be met by configuring the web server to utilize a
dedicated log tool that meets this requirement.
  "
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and deployment configuration settings
to determine if the web server log system provides a warning to the ISSO and SA
when allocated record storage volume reaches 75% of maximum record storage
capacity.

    If designated alerts are not sent or the web server is not configured to
use a dedicated log tool that meets this requirement, this is a finding.
  "
  desc  "fix", "Configure the web server to provide a warning to the ISSO and
SA when allocated log record storage volume reaches 75% of maximum record
storage capacity."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000359-WSR-000065"
  tag "gid": "V-55975"
  tag "rid": "SV-70229r2_rule"
  tag "stig_id": "SRG-APP-000359-WSR-000065"
  tag "fix_id": "F-60853r1_fix"
  tag "cci": ["CCI-001855"]
  tag "nist": ["AU-5 (1)", "Rev_4"]

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

