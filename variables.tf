variable "checkpointsase_api_key" {
  description = "API key (JWT) for the Check Point SASE Public API. Defaults to env var CHECKPOINT_SASE_API_KEY."
  type        = string
  sensitive   = true
  default     = null
}

variable "checkpointsase_base_url" {
  description = "Regional API endpoint. Defaults to the US endpoint if unset. Defaults to env var BASE_URL."
  type        = string
  default     = null
}
