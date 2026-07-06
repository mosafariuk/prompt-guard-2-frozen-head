provider "cloudflare" {
  api_token = var.cloudflare_api_token
}

provider "aws" {
  # Region and credentials from the standard AWS provider chain (env/profile).
  default_tags {
    tags = var.tags
  }
}

# The postgresql provider connects to the RDS instance to apply roles/migrations.
# It depends on the instance existing; see migrations.tf for the ordering.
provider "postgresql" {
  host            = aws_db_instance.threatlog.address
  port            = aws_db_instance.threatlog.port
  database        = var.db_name
  username        = var.db_master_username
  password        = var.db_master_password
  sslmode         = "require"
  connect_timeout = 15
  superuser       = false
}
