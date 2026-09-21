terraform {
  required_version = ">= 1.3.0"

  required_providers {
    checkpointsase = {
      source  = "CheckPointSW/checkpointsase"
      version = "~> 3.0"
    }
  }
}
