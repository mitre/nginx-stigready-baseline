control "V-56027" do
  title "The web server must only accept client certificates issued by DoD PKI
or DoD-approved PKI Certification Authorities (CAs)."
  desc  "Non-DoD approved PKIs have not been evaluated to ensure that they have
security controls and identity vetting procedures in place which are sufficient
for DoD systems to rely on the identity asserted in the certificate. PKIs
lacking sufficient security controls and identity vetting procedures risk being
compromised and issuing certificates that enable adversaries to impersonate
legitimate users."
  impact 0.5
  tag "gtitle": "SRG-APP-000427-WSR-000186"
  tag "gid": "V-56027"
  tag "rid": "SV-70281r2_rule"
  tag "stig_id": "SRG-APP-000427-WSR-000186"
  tag "fix_id": "F-60905r1_fix"
  tag "cci": ["CCI-002470"]
  tag "nist": ["SC-23 (5)", "Rev_4"]
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
  tag "check": "Review the web server deployed configuration to determine if
the web server will accept client certificates issued by unapproved PKIs. The
authoritative list of DoD-approved PKIs is published at
http://iase.disa.mil/pki-pke/interoperability.

If the web server will accept non-DoD approved PKI client certificates, this is
a finding."
  tag "fix": "Configure the web server to only accept DoD and DoD-approved PKI
client certificates."
end

