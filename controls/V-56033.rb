control "V-56033" do
  title "The web server must install security-relevant software updates within
the configured time period directed by an authoritative source (e.g. IAVM,
CTOs, DTMs, and STIGs)."
  desc  "Security flaws with software applications are discovered daily.
Vendors are constantly updating and patching their products to address newly
discovered security vulnerabilities. Organizations (including any contractor to
the organization) are required to promptly install security-relevant software
updates (e.g., patches, service packs, and hot fixes). Flaws discovered during
security assessments, continuous monitoring, incident response activities, or
information system error handling must also be addressed expeditiously.

    The web server will be configured to check for and install
security-relevant software updates from an authoritative source within an
identified time period from the availability of the update. By default, this
time period will be every 24 hours.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000456-WSR-000187"
  tag "gid": "V-56033"
  tag "rid": "SV-70287r2_rule"
  tag "stig_id": "SRG-APP-000456-WSR-000187"
  tag "fix_id": "F-60911r1_fix"
  tag "cci": ["CCI-002605"]
  tag "nist": ["SI-2 c", "Rev_4"]
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
determine if the web server checks for patches from an authoritative source at
least every 24 hours.

If there is no timeframe or the timeframe is greater than 24 hours, this is a
finding."
  tag "fix": "Configure the web server to check for patches and updates from an
authoritative source at least every 24 hours."
end

