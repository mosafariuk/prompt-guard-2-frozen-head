# Input variables. Secrets are marked sensitive and should come from a secrets
# manager / TF_VAR_* env, never committed. See terraform.tfvars.example.

variable "cloudflare_account_id" {
  type        = string
  description = "Cloudflare account ID that owns the Workers/KV/Queue/Hyperdrive."
}

variable "cloudflare_api_token" {
  type        = string
  sensitive   = true
  description = "Cloudflare API token with Workers/KV/Queues/Hyperdrive edit scope."
}

variable "origin_url" {
  type        = string
  description = "Origin LLM inference endpoint the firewall reverse-proxies to (boundary B2)."
}

variable "origin_shared_secret" {
  type        = string
  sensitive   = true
  description = "Edge->origin shared secret (X-Edge-Auth) authenticating boundary B2."
}

variable "max_body_bytes" {
  type        = number
  default     = 131072 # 128 KiB = N_max (Section III-C input bound)
  description = "Maximum accepted webhook body size; larger requests are rejected pre-scan."
}

variable "replay_tolerance_seconds" {
  type        = number
  default     = 300 # Section IV-E; matches Stripe's default tolerance window
  description = "Replay timestamp tolerance window Delta, in seconds."
}

# --- Database (RDS PostgreSQL) ------------------------------------------------
variable "db_engine_version" {
  type        = string
  default     = "16.4"
  description = "PostgreSQL major.minor. Declarative partitioning needs >=10, unique-key-on-partition >=11."
}

variable "db_instance_class" {
  type        = string
  default     = "db.r6g.large" # memory-optimized; sized for JSONB insert throughput
  description = "RDS instance class."
}

variable "db_allocated_storage" {
  type        = number
  default     = 200
  description = "Initial storage (GiB). gp3 for consistent WAL write IOPS."
}

variable "db_name" {
  type        = string
  default     = "threatlog"
  description = "Threat-log database name."
}

variable "db_master_username" {
  type    = string
  default = "tfadmin"
}

variable "db_master_password" {
  type      = string
  sensitive = true
}

variable "db_subnet_ids" {
  type        = list(string)
  description = "Existing private subnet IDs for the RDS subnet group (enterprise VPC)."
}

variable "db_vpc_security_group_ids" {
  type        = list(string)
  description = "Security groups permitting Hyperdrive/consumer egress to the DB port only."
}

variable "tags" {
  type    = map(string)
  default = { project = "edge-llm-firewall", compliance = "pci-dss-v4.0.1" }
}
