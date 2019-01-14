control "V-41704" do
  title "Users and scripts running on behalf of users must be contained to the
document root or home directory tree of the web server."
  desc  "A web server is designed to deliver content and execute scripts or
applications on the request of a client or user.  Containing user requests to
files in the directory tree of the hosted web application and limiting the
execution of scripts and applications guarantees that the user is not accessing
information protected outside the application's realm.

    The web server must also prohibit users from jumping outside the hosted
application directory tree through access to the user's home directory,
symbolic links or shortcuts, or through search paths for missing files.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000141-WSR-000087"
  tag "gid": "V-41704"
  tag "rid": "SV-54281r3_rule"
  tag "stig_id": "SRG-APP-000141-WSR-000087"
  tag "fix_id": "F-47163r2_fix"
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
determine where the document root or home directory for each application hosted
by the web server is located.

Verify that users of the web server applications, and any scripts running on
the user's behalf, are contained to each application's domain.

If users of the web server applications, and any scripts running on the user's
behalf, are not contained, this is a finding."
  tag "fix": "Configure the web server to contain users and scripts to each
hosted application's domain."
end

