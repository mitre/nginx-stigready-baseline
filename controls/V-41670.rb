# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-41670" do
  title "Web server log files must only be accessible by privileged users."
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
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and deployed configuration settings to
determine if the web server logging features protect log information from
unauthorized access.

    Review file system settings to verify the log files have secure file
permissions.

    If the web server log files are not protected from unauthorized access,
this is a finding.
  "
  desc  "fix", "Configure the web server log files so unauthorized access of
log information is not possible."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000118-WSR-000068"
  tag "gid": "V-41670"
  tag "rid": "SV-54247r3_rule"
  tag "stig_id": "SRG-APP-000118-WSR-000068"
  tag "fix_id": "F-47129r2_fix"
  tag "cci": ["CCI-000162"]
  tag "nist": ["AU-9", "Rev_4"]

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

