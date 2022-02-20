control 'V-56019' do
  title "An NGINX web server utilizing mobile code must meet DoD-defined mobile code
  requirements."
  desc "Mobile code in hosted applications allows the developer to add
  functionality and displays to hosted applications that are fluid, as opposed to
  a static web page. The data presentation becomes more appealing to the user, is
  easier to analyze, and navigation through the hosted application and data is
  much less complicated.

    Some mobile code technologies in use in today's applications are: Java,
  JavaScript, ActiveX, PDF, Postscript, Shockwave movies, Flash animations, and
  VBScript. The DoD has created policies that define the usage of mobile code on
  DoD systems. The usage restrictions and implementation guidance apply to both
  the selection and use of mobile code installed on organizational servers and
  mobile code downloaded and executed on individual workstations.

    The web server may host applications that contain mobile code and
  therefore, must meet the DoD-defined requirements regarding the deployment
  and/or use of mobile code. This includes digitally signing applets in order to
  provide a means for the client to establish application authenticity.
  "

  desc 'check', "Review the web server documentation and deployed configuration
  to determine whether mobile code used by hosted applications follows the DoD
  policies on the acquisition, development, and/or use of mobile code.

  If the web server does not implement mobile code, this check is Not Applicable.

  If the web server does implement mobile code but is not configured to follow
  the DoD policies on mobile code, this is a finding.
  "
  desc 'fix', "Configure the web server to follow the DoD policies on mobile
  code."
  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'SRG-APP-000206-WSR-000128'
  tag "gid": 'V-56019'
  tag "rid": 'SV-70273r2_rule'
  tag "stig_id": 'SRG-APP-000206-WSR-000128'
  tag "fix_id": 'F-60897r1_fix'
  tag "cci": ['CCI-001166']
  tag "nist": ['SC-18 (1)', '']

  if input('implements_mobile_code') == false
    impact 0.0
    describe 'This check is NA because NGINX does not implement mobile code.' do
      skip 'This check is NA because NGINX does not implement mobile code.'
    end
  else
    describe "This test requires a Manual Review: Verify the web server is configured
    to follow DoD policies on mobile code by reviewing the NGINX documentation." do
      skip "This test requires a Manual Review: Verify the web server is configured
      to follow DoD policies on mobile code by reviewing the NGINX documentation."
    end
  end
end
