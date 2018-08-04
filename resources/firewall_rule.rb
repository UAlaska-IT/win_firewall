# frozen_string_literal: true

# A firewall_rule describes the state of a single rule
# The post condition of the action is
#  1) The named rule exists
#  2) Every field of the rule is congruent with the corresponding field of the resource
# This resource will not modify external rules, but these can be disabled using the firewall_rule_state resource
resource_name :firewall_rule
provides :firewall_rule, os: 'windows'

default_action :create_synchronize

property :firewall_name, String, default: 'default' # The name of the associated firewall, used for logging

# These properties are required, but have default values
property :direction, String, default: 'in', equal_to: ['in', 'out']
property :firewall_action, String, default: 'allow', equal_to: ['allow', 'block', 'bypass']

# These properties are optional, but have default values that have no effect
# Each array must contain the single string 'any' or one or more allowed values
property :profiles, Array, default: ['any'] # Allowed values: 'domain', 'private', 'public'
property :interface_type, String, default: 'any', equal_to: ['any', 'wireless', 'lan', 'ras']
property :local_ips, Array, default: ['any'] # Allowed values: CIDRs as Strings, e.g. 192.168.1.0/24
property :local_ports, Array, default: ['any'] # Allowed values: integers
property :remote_ips, Array, default: ['any'] # Allowed values: CIDRs as Strings, e.g. 192.168.1.0/24
property :remote_ports, Array, default: ['any'] # Allowed values: integers
property :protocol, String, default: 'any', equal_to: ['any', 'icmpv4', 'icmpv6', 'tcp', 'udp']
property :service, String, default: 'any'
property :enabled, String, default: 'yes', equal_to: ['yes', 'no']

# These properties are optional, and have no reasonable default value
property :description, String, default: ''
property :program, String, default: ''

action :create_synchronize do
  create_synchronize_helper(@new_resource)
end

action_class.class_eval do
  include ::Firewall::Helper

  def create_synchronize_helper(new_resource)
    verify_or_update_firewall_rule(new_resource)
  end
end
