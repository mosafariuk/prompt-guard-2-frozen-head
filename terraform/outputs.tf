output "tenant_keys_kv_id" {
  value       = cloudflare_workers_kv_namespace.tenant_keys.id
  description = "KV namespace id for per-tenant HMAC keys -> edge-firewall/wrangler.toml."
}

output "nonce_cache_kv_id" {
  value       = cloudflare_workers_kv_namespace.nonce_cache.id
  description = "KV namespace id for the replay nonce cache."
}

output "threat_log_queue_name" {
  value       = cloudflare_queue.threat_log.name
  description = "Queue the firewall produces to and the consumer subscribes to."
}

output "hyperdrive_id" {
  value       = cloudflare_hyperdrive_config.threatlog.id
  description = "Hyperdrive config id -> db/consumer/wrangler.toml."
}

output "db_endpoint" {
  value       = aws_db_instance.threatlog.endpoint
  description = "RDS endpoint (host:port)."
}

output "consumer_login_role" {
  value       = postgresql_role.firewall_writer_login.name
  description = "INSERT-only login role for the consumer."
}

output "consumer_login_password" {
  value       = random_password.writer.result
  sensitive   = true
  description = "Password for the consumer login role (also embedded in Hyperdrive)."
}
