control "V-55987" do
  title "All accounts installed with the web server software and tools must
have passwords assigned and default passwords changed."
  desc  "During installation of the web server software, accounts are created
for the web server to operate properly. The accounts installed can have either
no password installed or a default password, which will be known and documented
by the vendor and the user community.

    The first things an attacker will try when presented with a login screen
are the default user identifiers with default passwords. Installed applications
may also install accounts with no password, making the login even easier. Once
the web server is installed, the passwords for any created accounts should be
changed and documented. The new passwords must meet the requirements for all
passwords, i.e., upper/lower characters, numbers, special characters, time
until change, reuse policy, etc.

    Service accounts or system accounts that have no login capability do not
need to have passwords set or changed.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000516-WSR-000079"
  tag "gid": "V-55987"
  tag "rid": "SV-70241r2_rule"
  tag "stig_id": "SRG-APP-000516-WSR-000079"
  tag "fix_id": "F-60865r1_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployment
configuration to determine what non-service/system accounts were installed by
the web server installation process.

Verify the passwords for these accounts have been set and/or changed from the
default passwords.

If these accounts still have no password or default passwords, this is a
finding."
  tag "fix": "Set passwords for non-service/system accounts containing no
passwords and change the passwords for accounts which still have default
passwords."
end

