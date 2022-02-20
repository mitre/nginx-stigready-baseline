control 'V-41745' do
  title "The NGINX web server must use cryptographic modules that meet the
  requirements of applicable federal laws, Executive Orders, directives,
  policies, regulations, standards, and guidance when encrypting stored data."
  desc "Encryption is only as good as the encryption modules utilized.
  Unapproved cryptographic module algorithms cannot be verified, and cannot be
  relied upon to provide confidentiality or integrity, and DoD data may be
  compromised due to weak algorithms.

    FIPS 140-2 is the current standard for validating cryptographic modules and
  NSA Type-X (where X=1, 2, 3, 4) products are NSA-certified, hardware-based
  encryption modules.

    The web server must provide FIPS-compliant encryption modules when storing
  encrypted data and configuration settings.
  "

  desc 'check', "Review NGINX web server documentation and deployed configuration
  to determine whether the encryption modules utilized for storage of data are FIPS 140-2
  compliant.

  Verify the Operating System and OpenSSL are in FIPS Mode -
  Execute the following command to check the OS:

    # sudo sysctl –a | grep fips

  If crypto.fips_enabled is set to 0, this is a finding.

  Execute the following command to check OpenSSL:
    # nginx -V

  The version of OpenSSL specified should include a '-fips'. If NGINX is not build with
  a version of OpenSSL that is FIPS compliant, this is a finding.
  "
  desc 'fix', "Configure the web server to utilize FIPS 140-2 approved
  encryption modules when the web server is storing data."

  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'SRG-APP-000179-WSR-000110'
  tag "gid": 'V-41745'
  tag "rid": 'SV-54322r3_rule'
  tag "stig_id": 'SRG-APP-000179-WSR-000110'
  tag "fix_id": 'F-47204r2_fix'
  tag "cci": ['CCI-000803']
  tag "nist": %w(IA-7)

  describe command('sysctl –a | grep fips') do
    its('stdout') { should eq "crypto.fips_enabled = 1\n" }
    its('exit_status') { should eq 0 }
  end

  describe command('nginx -V 2>&1').stdout do
    it { should match(/-fips/) }
  end
end
