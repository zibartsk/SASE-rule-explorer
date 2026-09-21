output "standard_networks" {
  description = "All standard (cloud-hosted) Harmony SASE networks."
  value       = data.checkpointsase_standard_networks.all.networks
}

output "enhanced_networks" {
  description = "All SD-WAN enhanced Harmony SASE networks."
  value       = data.checkpointsase_enhanced_networks.all.networks
}

locals {
  # Group ID(s) matching the "SASE_users" group name (normally just one).
  sase_users_group_ids = [
    for g in data.checkpointsase_groups.all.data : g.id if g.name == "SASE_users"
  ]
}

output "firewall_rules_with_sase_users_source" {
  description = "Access policy rules whose source includes the SASE_users group."
  value = [
    for rule in data.checkpointsase_access_policy.current.rule :
    rule if length([
      # rule.sources is an empty list on an unrestricted rule, otherwise one object
      # holding addresses/groups/users — flatten to check across all source entries.
      for src in rule.sources : true
      if length(setintersection(src.groups, local.sase_users_group_ids)) > 0
    ]) > 0
  ]
}

# Debug: list every group name so you can confirm the exact spelling/casing.
output "all_group_names" {
  value = [for g in data.checkpointsase_groups.all.data : g.name]
}

# Debug: every rule name alongside the raw group IDs in its source.
output "all_rule_sources" {
  value = {
    for rule in data.checkpointsase_access_policy.current.rule :
    rule.name => [for src in rule.sources : src.groups]
  }
}
