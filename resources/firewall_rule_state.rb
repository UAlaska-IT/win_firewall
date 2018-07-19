# frozen_string_literal: true

# These actions describe desired state using action verbs, but are idempotent
# For example, the :delete function does nothing if the named rule does not exist
# There are two cases for how the rule name is used
# 1) The name is used to find an exact match to the name of an existing rule
# 2) The name is a regex that will be used to match names of existing rules
# Regex matching will skip managed rules and respects the rule whitelist, but not the group whitelist
# Both the :enable and :disable functions describe the state of an extant rule
# An exception is raised if exact name matching is used and a non-extant rule is enabled or disabled
resource_name :firewall_rule_state
provides :firewall_rule_state, os: 'windows'

property :use_regex, [true, false], default: false
property :firewall_name, String, default: 'default' # The name of the associated firewall
property :ip_list, Array, default: []

extend ::Firewall::Helper

action :disable do
  disable_helper(@new_resource)
end

action :enable do
  enable_helper(@new_resource)
end

action :delete do
  delete_helper(@new_resource)
end

action :set_remote_ips do
  set_remote_ips_helper(@new_resource)
end

action_class.class_eval do
  include ::Firewall::Helper

  def disable_helper(new_resource)
    verify_matching_rules_are_disabled(new_resource)
  end

  def enable_helper(new_resource)
    verify_matching_rules_are_enabled(new_resource)
  end

  def delete_helper(new_resource)
    ensure_no_matching_external_rules_exist(new_resource)
  end

  def set_remote_ips_helper(new_resource)
    ensure_remote_ips_match(new_resource)
  end
end
