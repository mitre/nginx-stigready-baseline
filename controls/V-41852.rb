control "V-41852" do
  title "The web server must limit the character set used for data entry."
  desc  "Invalid user input occurs when a user inserts data or characters into
a hosted application's data entry field and the hosted application is
unprepared to process that data. This results in unanticipated application
behavior, potentially leading to an application compromise. Invalid user input
is one of the primary methods employed when attempting to compromise an
application.

    An attacker can also enter Unicode into hosted applications in an effort to
break out of the document home or root home directory or to bypass security
checks.

    The web server, by defining the character set available for data entry, can
trap efforts to bypass security checks or to compromise an application.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000251-WSR-000157"
  tag "gid": "V-41852"
  tag "rid": "SV-54429r3_rule"
  tag "stig_id": "SRG-APP-000251-WSR-000157"
  tag "fix_id": "F-47311r2_fix"
  tag "cci": ["CCI-001310"]
  tag "nist": ["SI-10", "Rev_4"]
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
  tag "check": "Review the web server documentation and deployed configuration
to determine what the data set is for data entry.

If the web server does not limit the data set used for data entry, this is a
finding."
  tag "fix": "Configure the web server to only accept the character sets
expected by the hosted applications."
end

