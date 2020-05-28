# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-41815" do
  title "Information at rest must be encrypted using a DoD-accepted algorithm
to protect the confidentiality and integrity of the information."
  desc  "Data at rest is inactive data which is stored physically in any
digital form (e.g., databases, data warehouses, spreadsheets, archives, tapes,
off-site backups, mobile devices, etc.). Data at rest includes, but is not
limited to, archived data, data which is not accessed or changed frequently,
files stored on hard drives, USB thumb drives, files stored on backup tape and
disks, and files stored off-site or on a storage area network.

    While data at rest can reside in many places, data at rest for a web server
is data on the hosting system storage devices. Data stored as a backup on tape
or stored off-site is no longer under the protection measures covered by the
web server.

    There are several pieces of data that the web server uses during operation.
The web server must use an accepted encryption method, such as SHA1, to protect
the confidentiality and integrity of the information.
  "
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and deployed configuration to locate
where potential data at rest is stored.

    Verify that the data is encrypted using a DoD-accepted algorithm to protect
the confidentiality and integrity of the information.

    If the data is not encrypted using a DoD-accepted algorithm, this is a
finding.
  "
  desc  "fix", "Use a DoD-accepted algorithm to encrypt data at rest to protect
the information's confidentiality and integrity."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000231-WSR-000144"
  tag "gid": "V-41815"
  tag "rid": "SV-54392r3_rule"
  tag "stig_id": "SRG-APP-000231-WSR-000144"
  tag "fix_id": "F-47274r2_fix"
  tag "cci": ["CCI-001199"]
  tag "nist": ["SC-28", "Rev_4"]

  describe "Skip Test" do
    skip "This is a manual check"
  end
  
end

