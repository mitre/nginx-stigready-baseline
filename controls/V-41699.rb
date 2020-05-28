# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-41699" do
  title "The web server must have Multipurpose Internet Mail Extensions (MIME)
that invoke OS shell programs disabled."
  desc  "Controlling what a user of a hosted application can access is part of
the security posture of the web server. Any time a user can access more
functionality than is needed for the operation of the hosted application poses
a security issue. A user with too much access can view information that is not
needed for the user's job role, or the user could use the function in an
unintentional manner.

    A MIME tells the web server what type of program various file types and
extensions are and what external utilities or programs are needed to execute
the file type.

    A shell is a program that serves as the basic interface between the user
and the operating system, so hosted application users must not have access to
these programs. Shell programs may execute shell escapes and can then perform
unauthorized activities that could damage the security posture of the web
server.
  "
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and deployment configuration to
determine if the OS shell is accessible by any MIME types that are enabled.

    If a user of the web server can invoke OS shell programs, this is a finding.
  "
  desc  "fix", "Configure the web server to disable all MIME types that invoke
OS shell programs."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000141-WSR-000081"
  tag "gid": "V-41699"
  tag "rid": "SV-54276r3_rule"
  tag "stig_id": "SRG-APP-000141-WSR-000081"
  tag "fix_id": "F-47158r2_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]

    # NOTE: This control is all wrong.  It is attempting to blacklist certain MIME 
  # types that might cause problems, but what it really should do is whitelist 
  # those MIME types that are safe.
  describe 'MathML' do
    it 'should not be in the file.' do
      expect(command('grep -w "text/mathml" ' + mime_type_path).stdout).to(eq "")
    end
  end
  describe 'Java App Descriptor' do
    it 'should not be in the file.' do
      expect(command('grep -w "text/vnd.sun.j2me.app-descriptor" ' + mime_type_path).stdout).to(eq "")
    end
  end
  describe 'Wireless Markup Language' do
    it 'should not be in the file.' do
      expect(command('grep -w "text/vnd.wap.wml" ' + mime_type_path).stdout).to(eq "")
    end
  end
  describe 'Java Archive' do
    it 'should not be in the file.' do
      expect(command('grep -w "application/java-archive" ' + mime_type_path).stdout).to(eq "")
    end
  end
  describe 'BinHex' do
    it 'should not be in the file.' do
      expect(command('grep -w "application/mac-binhex40" ' + mime_type_path).stdout).to(eq "")
    end
  end
  describe 'Postscript' do
    it 'should not be in the file.' do
      expect(command('grep -w "application/postscript" ' + mime_type_path).stdout).to(eq "")
    end
  end
  describe 'Binary WML' do
    it 'should not be in the file.' do
      expect(command('grep -w "application/vnd.wap.wmlc" ' + mime_type_path).stdout).to(eq "")
    end
  end
  describe 'Keyhole Markup Language' do
    it 'should not be in the file.' do
      expect(command('grep -w "application/vnd.google-earth.kml+xml" ' + mime_type_path).stdout).to(eq "")
    end
  end
  describe 'KML Archive' do
    it 'should not be in the file.' do
      expect(command('grep -w "application/vnd.google-earth.kmz" ' + mime_type_path).stdout).to(eq "")
    end
  end
  describe '7z Archive' do
    it 'should not be in the file.' do
      expect(command('grep -w "application/x-7z-compressed" ' + mime_type_path).stdout).to(eq "")
    end
  end
  describe 'Cocoa' do
    it 'should not be in the file.' do
      expect(command('grep -w "application/x-cocoa" ' + mime_type_path).stdout).to(eq "")
    end
  end
  describe 'Java Class File Diffs' do
    it 'should not be in the file.' do
      expect(command('grep -w "application/x-java-archive-diff" ' + mime_type_path).stdout).to(eq "")
    end
  end
  describe 'Java Web Start' do
    it 'should not be in the file.' do
      expect(command('grep -w "application/x-java-jnlp-file" ' + mime_type_path).stdout).to(eq "")
    end
  end
  describe 'Self-Extractable Archives' do
    it 'should not be in the file.' do
      expect(command('grep -w "application/x-makeself" ' + mime_type_path).stdout).to(eq "")
    end
  end
  describe 'Perl' do
    it 'should not be in the file.' do
      expect(command('grep -w "application/x-perl" ' + mime_type_path).stdout).to(eq "")
    end
  end
  # Palm Pilot files?  Are the 90's back?
  describe 'Palm Pilot Files' do
    it 'should not be in the file.' do
      expect(command('grep -w "application/x-pilot" ' + mime_type_path).stdout).to(eq "")
    end
  end
  describe 'RPM Package Manager' do
    it 'should not be in the file.' do
      expect(command('grep -w "application/x-redhat-package-manager" ' + mime_type_path).stdout).to(eq "")
    end
  end
  describe 'Self Extracting Archtives' do
    it 'should not be in the file.' do
      expect(command('grep -w "application/x-sea" ' + mime_type_path).stdout).to(eq "")
    end
  end
  # Flash - digital evil.
  describe 'Adobe Flash' do
    it 'should not be in the file.' do
      expect(command('grep -w "application/x-shockwave-flash" ' + mime_type_path).stdout).to(eq "")
    end
  end
  describe 'Stuffit' do
    it 'should not be in the file.' do
      expect(command('grep -w "application/x-stuffit" ' + mime_type_path).stdout).to(eq "")
      expect(command('grep -w "application/x-sit" ' + mime_type_path).stdout).to(eq "")
    end
  end
  describe 'Cross-Platform Installer Module' do
    it 'should not be in the file.' do
      expect(command('grep -w "application/x-xpinstall" ' + mime_type_path).stdout).to(eq "")
    end
  end
  # Includes bin, exe, dll, deb, dmg, iso, img, msi, msp, and msm.
  describe 'Binary Files' do
    it 'should not be in the file.' do
      expect(command('grep -w "application/octet-stream" ' + mime_type_path).stdout).to(eq "")
    end
  end
end

