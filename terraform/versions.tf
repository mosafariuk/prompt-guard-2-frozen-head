# Strict, exact provider pins for a reproducible, compliance-ready baseline.
# Rationale (Section VI-F posture): a floating provider version can silently
# change resource behavior between `apply`s — unacceptable for an auditable
# control environment. Pin EXACT versions here and COMMIT .terraform.lock.hcl so
# every operator resolves byte-identical provider binaries. Bump deliberately,
# via PR, not implicitly.

terraform {
  required_version = "= 1.9.8"

  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "= 4.52.0" # v4 resource schema (v5 is a breaking rewrite)
    }
    aws = {
      source  = "hashicorp/aws"
      version = "= 5.70.0"
    }
    postgresql = {
      source  = "cyrilgdn/postgresql"
      version = "= 1.25.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "= 3.6.3"
    }
    null = {
      source  = "hashicorp/null"
      version = "= 3.2.3"
    }
  }
}
