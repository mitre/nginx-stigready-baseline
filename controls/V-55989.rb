control "V-55989" do
  title "The web server must not perform user management for hosted
applications."
  desc  "User management and authentication can be an essential part of any
application hosted by the web server. Along with authenticating users, the user
management function must perform several other tasks like password complexity,
locking users after a configurable number of failed logins, and management of
temporary and emergency accounts; and all of this must be done enterprise-wide.

    The web server contains a minimal user management function, but the web
server user management function does not offer enterprise-wide user management,
and user management is not the primary function of the web server. User
management for the hosted applications should be done through a facility that
is built for enterprise-wide user management, like LDAP and Active Directory.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000141-WSR-000015"
  tag "gid": "V-55989"
  tag "rid": "SV-70243r2_rule"
  tag "stig_id": "SRG-APP-000141-WSR-000015"
  tag "fix_id": "F-60867r1_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]
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
  tag "check": "Review the web server documentation and configuration to
determine if the web server is being used as a user management application.

If the web server is being used to perform user management for the hosted
applications, this is a finding."
  tag "fix": "Configure the web server to disable user management
functionality."
end

