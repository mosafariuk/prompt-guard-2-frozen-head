# Schema migration + the application login role for the consumer.
#
# Flow: instance up -> run 001/002 as master (creates tables + NOLOGIN roles) ->
# create a LOGIN role for the consumer and grant it membership in the INSERT-only
# firewall_writer role. The consumer therefore inherits INSERT-only privileges;
# immutability (PCI-DSS 10.3.2) holds even for a compromised consumer credential.

resource "random_password" "writer" {
  length  = 32
  special = false # avoid connection-string quoting hazards
}

# Apply the SQL migrations. Re-runs only when a migration file changes (triggers).
resource "null_resource" "migrations" {
  triggers = {
    schema     = filemd5("${path.module}/../db/migrations/001_initial_schema.sql")
    management = filemd5("${path.module}/../db/migrations/002_partition_management.sql")
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    environment = {
      PGPASSWORD = var.db_master_password
    }
    command = <<-EOT
      set -euo pipefail
      CONN="host=${aws_db_instance.threatlog.address} port=${aws_db_instance.threatlog.port} dbname=${var.db_name} user=${var.db_master_username} sslmode=require"
      psql "$CONN" -v ON_ERROR_STOP=1 -f ${path.module}/../db/migrations/001_initial_schema.sql
      psql "$CONN" -v ON_ERROR_STOP=1 -f ${path.module}/../db/migrations/002_partition_management.sql
    EOT
  }

  depends_on = [aws_db_instance.threatlog]
}

# The consumer's login role (used via Hyperdrive). LOGIN + membership in the
# INSERT-only firewall_writer role created by 001.
resource "postgresql_role" "firewall_writer_login" {
  name     = "firewall_writer_app"
  login    = true
  password = random_password.writer.result

  depends_on = [null_resource.migrations]
}

resource "postgresql_grant_role" "writer_membership" {
  role       = postgresql_role.firewall_writer_login.name
  grant_role = "firewall_writer"
}
