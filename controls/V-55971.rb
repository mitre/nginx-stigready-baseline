# encoding: UTF-8
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')

control "V-55971" do
  title "The NGINX web server must be configurable to integrate with an organizations
security infrastructure."
  desc  "A web server will typically utilize logging mechanisms for maintaining
a historical log of activity that occurs within a hosted application. This
information can then be used for diagnostic purposes, forensics purposes, or
other purposes relevant to ensuring the availability and integrity of the
hosted application.

    While it is important to log events identified as being critical and
relevant to security, it is equally important to notify the appropriate
personnel in a timely manner so they are able to respond to events as they
occur.

    Manual review of the web server logs may not occur in a timely manner, and
each event logged is open to interpretation by a reviewer. By integrating the
web server into an overall or organization-wide log review, a larger picture of
events can be viewed, and analysis can be done in a timely and reliable manner.
  "
  desc  "rationale", ""
  desc  "check", "
  Review the NGINX web server documentation and deployed configuration to determine
  whether the web server is logging security-relevant events.

  Execute the following commands to verify that the NGINX web server is producing 
  logs and linking them to stdout and stderr:
  # readlink <access_log_path>/access.log
  # readlink <error_log_path>/error.log

  If the access.log and error.log files are not linked to stdout and stderr, 
  this is a finding.

  Work with the SIEM administrator to determine current security integrations.

  If the SIEM is not integrated with security, this is a finding.
  "
  desc  "fix", "Execute the following command on the NGINX web server to link logs 
  to stdout and stderr:
  # ln -sf /dev/stdout <access_log_path>/access.log
  # ln -sf /dev/stderr <access_log_path>/access.log
  
  Work with the SIEM administrator to integrate with an organizations security 
  infrastructure."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000358-WSR-000163"
  tag "gid": "V-55971"
  tag "rid": "SV-70225r2_rule"
  tag "stig_id": "SRG-APP-000358-WSR-000163"
  tag "fix_id": "F-60849r1_fix"
  tag "cci": ["CCI-001851"]
  tag "nist": ["AU-4 (1)", "Rev_4"]


  # Ensure access log is linked to stdout
  describe command('readlink ' + access_log_path) do
    its('stdout') { should eq "/dev/stdout\n" }
  end
  # Ensure error log is linked to stderror
  describe command('readlink ' + error_log_path)do
    its('stdout') { should eq "/dev/stderr\n" }
  end
  
  describe "Manual Step" do
    skip "Work with the SIEM administrator to determine current security integrations.
    If the SIEM is not integrated with security, this is a finding."
  end
end

