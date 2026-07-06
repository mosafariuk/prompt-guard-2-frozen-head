# Partitioned PostgreSQL instance (RDS) + a parameter group that ENCODES the
# high-velocity JSONB tuning of Section VI-D as infrastructure-as-code, so the
# tuning is auditable and reproducible rather than hand-applied.

resource "aws_db_subnet_group" "threatlog" {
  name       = "threatlog-subnets"
  subnet_ids = var.db_subnet_ids
}

# Parameter group = postgresql.conf.tuning, as code. Provenance tags match the
# ledger: [VERIFIED] primary-sourced; [PRACTICE] standard guidance.
resource "aws_db_parameter_group" "threatlog" {
  name   = "threatlog-pg16"
  family = "postgres16"

  # [VERIFIED] WAL durability/throughput (dynamic).
  parameter {
    name         = "synchronous_commit"
    value        = "off"
    apply_method = "immediate"
  }
  parameter {
    name         = "commit_delay"
    value        = "100" # microseconds
    apply_method = "immediate"
  }
  parameter {
    name         = "commit_siblings"
    value        = "5"
    apply_method = "immediate"
  }
  # [PRACTICE] cut WAL volume on write-heavy load.
  parameter {
    name         = "wal_compression"
    value        = "on"
    apply_method = "immediate"
  }
  # [VERIFIED] checkpoint spreading/spacing (max_wal_size dynamic; sizes in MB).
  parameter {
    name         = "checkpoint_timeout"
    value        = "900"
    apply_method = "immediate"
  }
  parameter {
    name         = "max_wal_size"
    value        = "16384"
    apply_method = "immediate"
  }
  parameter {
    name         = "min_wal_size"
    value        = "2048"
    apply_method = "immediate"
  }
  parameter {
    name         = "checkpoint_completion_target"
    value        = "0.9"
    apply_method = "immediate"
  }
  # [PRACTICE] memory (static -> reboot). shared_buffers ~25% of instance RAM;
  # unit is 8 kB pages, so bytes/32768 ~= 25%.
  parameter {
    name         = "shared_buffers"
    value        = "{DBInstanceClassMemory/32768}"
    apply_method = "pending-reboot"
  }
  parameter {
    name         = "wal_buffers"
    value        = "2048" # 8 kB units = 16 MB
    apply_method = "pending-reboot"
  }
  # [VERIFIED] GIN pending-list global default (per-index override lives in 001).
  parameter {
    name         = "gin_pending_list_limit"
    value        = "8192" # kB
    apply_method = "immediate"
  }
  # [PRACTICE] aggressive autovacuum/analyze for append-only high-insert tables.
  parameter {
    name         = "autovacuum_naptime"
    value        = "30"
    apply_method = "immediate"
  }
  parameter {
    name         = "autovacuum_vacuum_scale_factor"
    value        = "0.05"
    apply_method = "immediate"
  }
  parameter {
    name         = "autovacuum_analyze_scale_factor"
    value        = "0.02"
    apply_method = "immediate"
  }
}

resource "aws_db_instance" "threatlog" {
  identifier     = "threatlog"
  engine         = "postgres"
  engine_version = var.db_engine_version
  instance_class = var.db_instance_class

  allocated_storage     = var.db_allocated_storage
  max_allocated_storage = var.db_allocated_storage * 4 # storage autoscaling headroom
  storage_type          = "gp3"
  storage_encrypted     = true # PCI-DSS: protect stored data at rest

  db_name  = var.db_name
  username = var.db_master_username
  password = var.db_master_password

  db_subnet_group_name   = aws_db_subnet_group.threatlog.name
  vpc_security_group_ids = var.db_vpc_security_group_ids
  parameter_group_name   = aws_db_parameter_group.threatlog.name

  multi_az                     = true  # availability (SOC 2 A-series)
  publicly_accessible          = false # DB never exposed to the internet
  backup_retention_period      = 35    # supports the audit-retention posture
  deletion_protection          = true
  performance_insights_enabled = true
  apply_immediately            = false

  # A parameter-group change on static params requires a reboot; manage that in a
  # maintenance window rather than on every apply.
  skip_final_snapshot = false
  final_snapshot_identifier = "threatlog-final"
}
