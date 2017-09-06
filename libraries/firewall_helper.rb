# frozen_string_literal: true

include Chef::Mixin::PowershellOut

# Four name spaces come into play
# 1) The 'internal' space uses attribute names for hash keys, and all CIDRs are normalized
# All other spaces are thin interfaces that are converted to the 'internal' working namespace
# 2) The 'client' space is identical to 'internal' space except CIDRs may not be normalized
# 3) The 'query' space interfaces with netsh output formatting
# 4) The 'command' space interfaces with netsh input formatting

module Firewall
  # This module implements helpers that are used for Firewall resources
  module Helper
    @@managed_rule_list = []
    @@firewall_log_files = {} # A hash firewall.name => firewall.log_file
    @@creation_script_cache = {} # A hash firewall.name => all creation scripts on the node

    def ensure_non_null_array_entry(hash, key)
      hash[key] = [] unless hash.key?(key)
    end

    # Returns true iff a new firewall was initialized
    def ensure_firewall_exists(firewall)
      @@firewall_log_files[firewall.name] = firewall.log_file
      ensure_non_null_array_entry(node['win_firewall']['firewall_to_whitelist_groups'], firewall.name)
      ensure_non_null_array_entry(node['win_firewall']['firewall_to_whitelist_rules'], firewall.name)
    end

    def create_log_file(firewall, creation_script)
      # Debug usage; not logically a resource
      File.write(@@firewall_log_files[firewall.name], creation_script)
    end

    def ensure_log_scripts_exist(firewall)
      creation_script = if @@creation_script_cache[firewall.name].nil?
                          'No firewall rules created'
                        else
                          @@creation_script_cache[firewall.name].join("\r\n")
                        end
      create_log_file(firewall, creation_script)
    end

    # The following two functions map 'query' space to 'internal' space
    # Map netsh output to resource property names
    MAPPED_KEYS = {
      'rule name' => 'name',
      'localip' => 'local_ips',
      'remoteip' => 'remote_ips',
      'localport' => 'local_ports',
      'remoteport' => 'remote_ports',
      'interfacetypes' => 'interface_type',
      'action' => 'firewall_action'
    }.freeze

    def key_map(key)
      return MAPPED_KEYS[key] if MAPPED_KEYS.key?(key)
      return key
    end

    # Map netsh output to resource property values
    def val_map(key, val)
      return 'any' if key == 'profiles' && val == 'domain,private,public'
      return val
    end

    def line_matches_or_empty?(line, regex)
      return true if empty_string?(line) # Happens on the edges
      return true if line.match?(/^-/) # Horizontal rule for header
      return true if line.match?(regex) # Header or footer
      return false
    end

    def parse_key_value_lines(rule_hash, paragraph)
      paragraph.lines do |line|
        next if line_matches_or_empty?(line, /^Ok/) # The last line from the command

        key, v0 = line.split(': ') # Must include space or it breaks program paths
        key = key.downcase.chomp
        val = v0&.strip # v0 will be nil if the line was not split
        val = v0 if val.nil? # val might not have been set, or was set to nil if v0 was unmodified by strip
        next if val.nil? || val.empty?
        val = val.downcase

        rule_hash[key_map(key)] = val_map(key, val)
      end
    end

    def empty_string?(string)
      return string.nil? || string.empty? || string == ''
    end

    def empty_rule?(rule_hash)
      empty_string?(rule_hash['name'])
    end

    def log_powershell_out(script_name, script_code)
      Chef::Log.debug("Running #{script_name} script: '#{script_code}'")
      cmd = powershell_out(script_code)
      Chef::Log.debug("Returned from #{script_name} script: '#{cmd.stdout}'")
      return cmd
    end

    def parse_firewall_paragraphs(cmd)
      count = 0
      retval = []
      cmd.stdout.to_s.split(/^\s*$/).each do |paragraph| # Split at empty lines
        count += 1
        rule = {}
        parse_key_value_lines(rule, paragraph)
        retval.push(rule) unless empty_rule?(rule)
      end
      Chef::Log.debug("Processed #{count} paragraphs, found #{retval.size} rules")
      return retval
    end

    # Parse all firewall rules as an array of hashes
    # Keys and values will be in lowercase
    def parse_firewall_rules
      script_code = 'netsh advfirewall firewall show rule name=all verbose'
      cmd = powershell_out(script_code) # Not logged because it makes too much noise

      retval = parse_firewall_paragraphs(cmd)

      raise 'Could not parse firewall rules' if retval.empty?
      return retval
    end

    # Return true iff a rule exists
    def firewall_rule_exists?(rule_name)
      script_code = "netsh advfirewall firewall show rule name=\'#{rule_name}\' verbose"
      cmd = log_powershell_out('exist', script_code)
      return cmd.stdout !~ /No rules match/
    end

    # Parse a single firewall rule into a hash
    # Keys and values will be in lowercase
    def parse_firewall_rule(rule_name)
      raise "Firewall rule '#{rule_name}' does not exist." unless firewall_rule_exists?(rule_name)

      script_code = "netsh advfirewall firewall show rule name=\'#{rule_name}\' verbose"
      cmd = log_powershell_out('parse', script_code)
      rule = {}
      parse_key_value_lines(rule, cmd.stdout)
      return rule
    end

    # This function maps 'client' space to 'internal' space
    # Standardized CIDRs to match netsh format
    def standardize_cidrs(ips)
      retval = []
      ips.each do |ip|
        retval.push(ip.include?('any') || ip.include?('/') || ip.include?('-') ? ip.strip : ip.strip + '/32')
      end
      return retval.join(',')
    end

    def copy_rule_properties(rule) # rubocop:disable Metrics/MethodLength, Metrics/AbcSize
      return {
        'name' => rule.name,
        'direction' => rule.direction,
        'firewall_action' => rule.firewall_action,
        'profiles' => rule.profiles.join(','),
        'interface_type' => rule.interface_type,
        'local_ips' => standardize_cidrs(rule.local_ips),
        'local_ports' => rule.local_ports.join(','),
        'remote_ips' => standardize_cidrs(rule.remote_ips),
        'remote_ports' => rule.remote_ports.join(','),
        'protocol' => rule.protocol,
        'service' => rule.service,
        'enabled' => rule.enabled,
        'description' => rule.description,
        'program' => rule.program
      }
    end

    # Convert a rule to a hash to allow comparison with shell output
    # We also do our error checking here for some reason
    def rule2hash(rule)
      if rule.protocol.include?('icmp') && (rule.local_ports.first != 'any' || rule.remote_ports.first != 'any')
        raise "Rule #{rule.name} includes ICMP and specifies ports"
      end
      return copy_rule_properties(rule)
    end

    # This function maps 'internal' space to 'command' space
    # Map resource property names to netsh commands
    def cmd_map(key) # rubocop:disable Metrics/MethodLength
      return {
        'direction' => 'dir',
        'firewall_action' => 'action',
        'enabled' => 'enable',
        'profiles' => 'profile',
        'local_ips' => 'localip',
        'remote_ips' => 'remoteip',
        'local_ports' => 'localport',
        'remote_ports' => 'remoteport',
        'interface_type' => 'interfacetype',
        'edge traversal' => 'edge' # This comes from parsed-modified rules
      }[key] || key
    end

    def filter_or_append_rule_field(script_code, key, val) # rubocop:disable Metrics/AbcSize
      if empty_string?(val)
        # Filter empty values
      elsif (key == 'local_ports' || key == 'remote_ports') && val == 'any'
        # Any port must be implicit for everything but TCP/UDP, so just filter it
      elsif ['name', 'description', 'program'].include?(key)
        # May have spaces, so quote it
        script_code << ' ' + cmd_map(key) + "='" + val + "'"
      else
        script_code << ' ' + cmd_map(key) + '=' + val
      end
    end

    def validate_creation_output(output)
      return if output.match?(/^Ok./)
      Chef::Log.error("Error creating firewall rule:\r\n#{output}")
      raise 'Error creating firewall rule'
    end

    # Add a new firewall rule
    def create_firewall_rule(rule_hash, firewall_name)
      script_code = String.new('netsh advfirewall firewall add rule')
      rule_hash.each do |key, val|
        filter_or_append_rule_field(script_code, key, val)
      end
      @@creation_script_cache[firewall_name] = [] if @@creation_script_cache[firewall_name].nil?
      @@creation_script_cache[firewall_name].push(script_code)
      cmd = log_powershell_out('creation', script_code)
      validate_creation_output(cmd.stdout)
    end

    def delete_firewall_rule(rule_name)
      script_code = "netsh advfirewall firewall delete rule name='#{rule_name}'"
      log_powershell_out('deletion', script_code)
    end

    def log_system_rule_error?(existing_rule, new_rule)
      if !existing_rule['grouping'].nil? && !existing_rule['grouping'].empty?
        message = "Firewall rule '#{new_rule['name']}' is part of system group '#{existing_rule['grouping']}'"\
          ' and cannot be managed.  Delete this rule and create the desired rule instead.'
        Chef::Log.error(message)
        return true
      end
      return false
    end

    def log_group_policy_error?(existing_rule, new_rule)
      if !existing_rule['rule source'].nil? && existing_rule['rule source'] != 'local setting'
        message = "Firewall rule '#{new_rule['name']}' is set by group policy '#{existing_rule['rule source']}'"\
          ' and cannot be managed.  Delete this rule and create the desired rule instead.'
        Chef::Log.error(message)
        return true
      end
      return false
    end

    # Determine if an existing rule is manageable
    # Log an error if an attempt is made to modify a built-in rule or a rule set by group policy
    def check_and_log_managed_rule?(new_rule)
      existing_rule = parse_firewall_rule(new_rule['name'])
      return true if log_system_rule_error?(existing_rule, new_rule)
      return true if log_group_policy_error?(existing_rule, new_rule)
      return false
    end

    def hash_to_lines(hash)
      retval = String.new('{')
      hash.each do |key, val|
        retval << "\r\n  #{key} = #{val}"
      end
      retval << "\r\n}"
    end

    def filter_rule_field_diff?(existing_rule, key, val) # rubocop:disable Metrics/CyclomaticComplexity
      return true if empty_string?(val)
      # This catches most cases of equality
      return true if existing_rule.key?(key) && existing_rule[key] == val.downcase
      # Any does not show up in the query
      return true if key.match?(/ports/) && val == 'any' && !existing_rule.key?(key)
      return false
    end

    # Diffs to CIDR strings
    def diff_ips(ips1, ips2)
      retval = []
      ips1.split(',').each do |ip|
        retval.push(ip) unless ips2.include?(ip)
      end
      ips2.split(',').each do |ip|
        retval.push(ip) unless ips1.include?(ip)
      end
      return retval
    end

    def diff_rule_ips(existing_rule, key, val, diff)
      ip_diff = diff_ips(val, existing_rule[key])
      diff.push(key) unless ip_diff.empty?
    end

    def diff_rule_field(diff, existing_rule, key, val)
      return if filter_rule_field_diff?(existing_rule, key, val)
      if key.match?(/ips/) # These are joined strings, and possibly reordered
        diff_rule_ips(existing_rule, key, val, diff)
      else
        diff.push(key)
      end
    end

    def log_rule_diff(existing_rule, new_rule, diff)
      return if diff.empty?
      Chef::Log.debug("Diff fields: #{diff}")
      Chef::Log.debug("New rule: #{hash_to_lines(new_rule)}")
      Chef::Log.debug("Existing rule: #{hash_to_lines(existing_rule)}")
    end

    # Determine if an existing rule matches a rule resource
    # Compare each parameter of the new resource with the corresponding rule field
    def get_rule_diff(new_rule_hash)
      existing_rule = parse_firewall_rule(new_rule_hash['name'])
      diff = []
      new_rule_hash.each do |key, val| # Only compare fields that exist in the firewall_rule resource
        diff_rule_field(diff, existing_rule, key, val)
      end
      log_rule_diff(existing_rule, new_rule_hash, diff)
      return diff
    end

    def create_non_extant_rule?(rule_hash, firewall_name)
      return false if firewall_rule_exists?(rule_hash['name'])

      Chef::Log.debug("Creating firewall rule '#{rule_hash['name']}'")
      converge_by "Create Firewall Rule #{rule_hash['name']}" do # ~FC005 # Repetition of declarations??
        create_firewall_rule(rule_hash, firewall_name)
      end
      return true
    end

    def update_extant_rule?(rule_hash, firewall_name, modify_managed)
      rule_diff = get_rule_diff(rule_hash)
      return false if rule_diff.empty? || (!modify_managed && check_and_log_managed_rule?(rule_hash))

      # Rules are immutable: if we attempt to update an existing rule, we end up with two rules with the same name
      converge_by "Update Firewall Rule #{rule_hash['name']}" do
        Chef::Log.debug("Deleting firewall rule '#{rule_hash['name']}'")
        delete_firewall_rule(rule_hash['name'])
        Chef::Log.debug("Re-creating firewall rule '#{rule_hash['name']}'")
        create_firewall_rule(rule_hash, firewall_name)
      end
      return true
    end

    def verify_or_update_firewall_hash(rule_hash, firewall_name)
      @@managed_rule_list.push(rule_hash['name'].downcase)
      create_non_extant_rule?(rule_hash, firewall_name) || update_extant_rule?(rule_hash, firewall_name, false)
    end

    # Check if an existing rule matches the passed rule
    # Return true iff the rule is changed (create or replaced as needed)
    def verify_or_update_firewall_rule(rule)
      verify_or_update_firewall_hash(rule2hash(rule), rule.firewall_name)
    end

    # Return true iff the rule exists and was enabled (and is now disabled)
    def verify_rule_exists_and_is_disabled(rule_name, _firewall_name, _data)
      unless firewall_rule_exists?(rule_name)
        raise "Firewall rule '#{rule_name}' does not exist so cannot be disabled"
      end
      rule = parse_firewall_rule(rule_name)
      return if rule['enabled'] == 'no'
      converge_by "Disable firewall rule #{rule_name}" do
        script_code = "netsh advfirewall firewall set rule name='#{rule_name}' new enable=no"
        log_powershell_out('disable', script_code)
      end
    end

    # Return true iff the rule exists and was disabled (and is now enabled)
    def verify_rule_exists_and_is_enabled(rule_name, _firewall_name, _data)
      unless firewall_rule_exists?(rule_name)
        raise "Firewall rule '#{rule_name}' does not exist so cannot be enabled"
      end
      rule = parse_firewall_rule(rule_name)
      return if rule['enabled'] == 'yes'
      converge_by "Enable firewall rule #{rule_name}" do
        script_code = "netsh advfirewall firewall set rule name='#{rule_name}' new enable=yes"
        log_powershell_out('enable', script_code)
      end
    end

    # Return true iff the rule existed (and now does not)
    def verify_rule_does_not_exist(rule_name, _firewall_name, _data)
      if firewall_rule_exists?(rule_name)
        Chef::Log.debug("Deleting rule '#{rule_name}'")
        converge_by "Delete firewall rule #{rule_name}" do
          delete_firewall_rule(rule_name)
        end
      else
        Chef::Log.debug("Skipped deleting rule '#{rule_name}'")
      end
    end

    def modify_parsed_rule(rule_hash)
      rule_hash.delete('grouping')
      rule_hash.delete('rule source')
      Chef::Log.debug("Rule hash with new IPs: #{rule_hash}")
    end

    def verify_rule_ips_match(rule_name, firewall_name, remote_ips)
      Chef::Log.debug("Verifying rule IPs for rule #{rule_name}")
      unless firewall_rule_exists?(rule_name)
        raise "Firewall rule '#{rule_name}' does not exist so cannot have remote IPs changed"
      end
      rule_hash = parse_firewall_rule(rule_name)
      Chef::Log.debug("Rule hash original: #{rule_hash}")
      rule_hash['remote_ips'] = standardize_cidrs(remote_ips)
      modify_parsed_rule(rule_hash)
      @@managed_rule_list.push(rule_hash['name'].downcase)
      update_extant_rule?(rule_hash, firewall_name, true)
    end

    def rule_group_is_whitelisted?(firewall_name, rule)
      return node['win_firewall']['firewall_to_whitelist_groups'][firewall_name].include?(rule['grouping'])
    end

    def rule_is_whitelisted?(rule, firewall_name, whitelist_groups)
      # Whitelisted group?
      if whitelist_groups && rule_group_is_whitelisted?(firewall_name, rule)
        Chef::Log.debug("Rule '#{rule['name']}' skipped because group '#{rule['grouping']}' was whitelisted")
      # Whitelisted rule?
      elsif node['win_firewall']['firewall_to_whitelist_rules'][firewall_name].include?(rule['name'])
        Chef::Log.debug("Rule '#{rule['name']}' skipped because it was explicity whitelisted")
      else
        return false
      end
      return true
    end

    def rule_can_be_managed?(rule, firewall_name, whitelist_groups)
      # Skip whitelisted rules
      return false if rule_is_whitelisted?(rule, firewall_name, whitelist_groups)
      # Skip managed rules
      if @@managed_rule_list.include?(rule['name'])
        Chef::Log.debug("Rule '#{rule['name']}' skipped because it was managed")
        return false
      end
      return true
    end

    def log_and_call_state_function(func, rule, rule_state, data)
      Chef::Log.info("Rule '#{rule['name']}' modified due to regex /#{rule_state.name}/")
      func.call(rule['name'], rule_state.firewall_name, data)
    end

    def call_function_for_matching_rule(func, rule, rule_state, data)
      return unless rule_can_be_managed?(rule, rule_state.firewall_name, false)
      if rule['name'].match?(Regexp.new(rule_state.name))
        log_and_call_state_function(func, rule, rule_state, data)
      else
        Chef::Log.debug("Rule '#{rule['name']}' skipped due to regex /#{rule_state.name}/")
      end
    end

    def modify_matching_rules(func, rule_state, data)
      Chef::Log.debug("Resource list: '#{@@managed_rule_list}'")

      return func.call(rule_state.name, rule_state.firewall_name, data) unless rule_state.use_regex

      parse_firewall_rules.each do |rule|
        call_function_for_matching_rule(func, rule, rule_state, data)
      end
    end

    # Disable matching firewall rules that are not whitelisted or managed with Chef
    # Return true iff any non-whitelisted, external rule was enabled (and is now disabled)
    def verify_matching_rules_are_disabled(rule_state)
      modify_matching_rules(method(:verify_rule_exists_and_is_disabled), rule_state, nil)
    end

    # Enable matching firewall rules that are not whitelisted or managed with Chef
    # Return true iff any non-whitelisted, external rule was disabled (and is now enabled)
    def verify_matching_rules_are_enabled(rule_state)
      modify_matching_rules(method(:verify_rule_exists_and_is_enabled), rule_state, nil)
    end

    # Delete matching firewall rules that are not whitelisted or managed with Chef
    # Return true iff any non-whitelisted, external rule existed (and now does not)
    def ensure_no_matching_external_rules_exist(rule_state)
      modify_matching_rules(method(:verify_rule_does_not_exist), rule_state, nil)
    end

    # Replace firewall rule with an otherwise identical rule that limits remote IPs to the specified CIDRs
    def ensure_remote_ips_match(rule_state)
      modify_matching_rules(method(:verify_rule_ips_match), rule_state, rule_state.ip_list)
    end

    def call_function_for_external_rule(func, rule, firewall, disabled_only)
      return unless rule_can_be_managed?(rule, firewall.name, true)
      # Skip disabled rules?
      if disabled_only && rule['enabled'] != 'no'
        Chef::Log.debug("Rule '#{rule['name']}' whitelisted because it was enabled")
      else
        Chef::Log.info("Rule '#{rule['name']}' modified due to firewall action (not whitelisted)")
        func.call(rule['name'], firewall.name, nil)
      end
    end

    def modify_external_rules(func, firewall, disabled_only)
      firewall_rules = parse_firewall_rules
      Chef::Log.debug("Resource list: '#{@@managed_rule_list}'")

      firewall_rules.each do |rule|
        call_function_for_external_rule(func, rule, firewall, disabled_only)
      end
    end

    # Disable firewall rules that are not whitelisted or managed with Chef
    # Return true iff any non-whitelisted, external rule was enabled (and is now disabled)
    def ensure_external_rules_are_disabled(firewall)
      modify_external_rules(method(:verify_rule_exists_and_is_disabled), firewall, false)
    end

    # Delete firewall rules that are not whitelisted or managed with Chef
    # Return true iff any non-whitelisted, external rule existed (and now does not)
    def ensure_no_external_rules_exist(firewall)
      modify_external_rules(method(:verify_rule_does_not_exist), firewall, false)
    end

    # Delete firewall rules that are not whitelisted or managed with Chef or enabled
    # Return true iff any non-whitelisted, external, enabled rule existed (and now does not)
    def ensure_no_external_disabled_rules_exist(firewall)
      modify_external_rules(method(:verify_rule_does_not_exist), firewall, true)
    end

    def log_and_call_group_function(func, rule, rule_group)
      Chef::Log.info("Rule '#{rule['name']}' modified due to group '#{rule['grouping']}'")
      func.call(rule['name'], rule_group.firewall_name, nil)
    end

    def call_function_for_group_rule(func, rule, rule_group)
      return unless rule_can_be_managed?(rule, rule_group.firewall_name, false)
      # Group matches
      if rule['grouping'] == rule_group.name.downcase
        log_and_call_group_function(func, rule, rule_group)
      # Group does not match
      else
        Chef::Log.debug("Rule '#{rule['name']}' skipped due to group '#{rule['grouping']}'")
      end
    end

    def modify_firewall_group(func, rule_group)
      firewall_rules = parse_firewall_rules
      Chef::Log.debug("Resource list: '#{@@managed_rule_list}'")

      firewall_rules.each do |rule|
        call_function_for_group_rule(func, rule, rule_group)
      end
    end

    def verify_group_is_enabled(rule_group)
      modify_firewall_group(method(:verify_rule_exists_and_is_enabled), rule_group)
    end

    def verify_group_is_disabled(rule_group)
      modify_firewall_group(method(:verify_rule_exists_and_is_disabled), rule_group)
    end

    def verify_group_does_not_exist(rule_group)
      modify_firewall_group(method(:verify_rule_does_not_exist), rule_group)
    end
  end
end
