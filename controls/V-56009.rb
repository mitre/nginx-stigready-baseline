control "V-56009" do
  title "Cookies exchanged between the web server and the client, such as
session cookies, must have cookie properties set to force the encryption of
cookies."
  desc  "Cookies can be sent to a client using TLS/SSL to encrypt the cookies,
but TLS/SSL is not used by every hosted application since the data being
displayed does not require the encryption of the transmission. To safeguard
against cookies, especially session cookies, being sent in plaintext, a cookie
can be encrypted before transmission. To force a cookie to be encrypted before
transmission, the cookie Secure property can be set."
  impact 0.5
  tag "gtitle": "SRG-APP-000439-WSR-000155"
  tag "gid": "V-56009"
  tag "rid": "SV-70263r2_rule"
  tag "stig_id": "SRG-APP-000439-WSR-000155"
  tag "fix_id": "F-60887r1_fix"
  tag "cci": ["CCI-002418"]
  tag "nist": ["SC-8", "Rev_4"]
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
to verify that cookies are encrypted before transmission.

If the web server is not configured to encrypt cookies, this is a finding."
  tag "fix": "Configure the web server to encrypt cookies before transmission."
end

