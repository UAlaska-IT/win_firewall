# frozen_string_literal: true

name 'win_firewall'
maintainer 'OIT Systems Engineering'
maintainer_email 'ua-oit-se@alaska.edu'
license 'MIT'
description 'Provides resources for configuring the firewall in Windows'
long_description IO.read(File.join(File.dirname(__FILE__), 'README.md'))
issues_url 'https://github.alaska.edu/oit-cookbooks/win_firewall/issues' if respond_to?(:issues_url)
source_url 'https://github.alaska.edu/oit-cookbooks/win_firewall' if respond_to?(:source_url)

version '1.0.0'

supports 'windows', '>= 10.0' # Windows 10 or Server 2016, see https://en.wikipedia.org/wiki/List_of_Microsoft_Windows_versions

chef_version '~> 13.1.0' if respond_to?(:chef_version)
ohai_version '>= 13.1.0' if respond_to?(:ohai_version)

depends 'windows', '~> 3.1.1'
