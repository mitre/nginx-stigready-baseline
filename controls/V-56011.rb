control "V-56011" do
  title "A web server must maintain the confidentiality of controlled
information during transmission through the use of an approved TLS version."
  desc  "Transport Layer Security (TLS) is a required transmission protocol for
a web server hosting controlled information. The use of TLS provides
confidentiality of data in transit between the web server and client. FIPS
140-2 approved TLS versions must be enabled and non-FIPS-approved SSL versions
must be disabled.

    NIST SP 800-52 defines the approved TLS versions for government
applications.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000439-WSR-000156"
  tag "gid": "V-56011"
  tag "rid": "SV-70265r2_rule"
  tag "stig_id": "SRG-APP-000439-WSR-000156"
  tag "fix_id": "F-60889r1_fix"
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
to determine which version of TLS is being used.

If the TLS version is not an approved version according to NIST SP 800-52 or
non-FIPS-approved algorithms are enabled, this is a finding."
  tag "fix": "Configure the web server to use an approved TLS version according
to NIST SP 800-52 and to disable all non-approved versions."
end

