provider "checkpointsase" {
  # Prefer the CHECKPOINT_SASE_API_KEY / BASE_URL env vars over these variables
  # so the key never ends up in state or version control.
  api_key  = var.checkpointsase_api_key
  base_url = var.checkpointsase_base_url
}

# Standard (cloud-hosted) networks, flat shape.
data "checkpointsase_standard_networks" "all" {}

# SD-WAN enhanced networks.
data "checkpointsase_enhanced_networks" "all" {}

# Whole ordered firewall (web access) policy for the tenant.
data "checkpointsase_access_policy" "current" {}

# Access groups, to resolve the "SASE_users" group name to its ID —
# rule.sources.groups stores group IDs, not names.
data "checkpointsase_groups" "all" {
  limit = 1000
}

# Shared address objects, to resolve destination address IDs to names.
data "checkpointsase_object_addresses" "all" {}

# Shared service objects, to resolve rule service IDs to names.
data "checkpointsase_object_services" "all" {}


