# Terraform — Infrastructure Provisioning

Provisions the stateful baseline: Cloudflare KV / Queue / Hyperdrive + the edge
firewall Worker, and an RDS PostgreSQL instance whose parameter group encodes the
Section VI-D tuning as code.

## Provider pinning (compliance baseline)

All providers are pinned to EXACT versions in `versions.tf` and the resolved
`.terraform.lock.hcl` **must be committed**. This guarantees byte-identical
provider binaries across operators — a reproducibility requirement for an
auditable (PCI-DSS / SOC 2) control environment. Upgrade deliberately via PR.

## Prerequisites

- `terraform` 1.9.8, `psql` on PATH (for the migration `local-exec`), AWS creds,
  a Cloudflare API token (`TF_VAR_cloudflare_api_token`).
- The edge Worker bundle must be built first (Terraform does not bundle TS):

```bash
cd ../edge-firewall
npx wrangler deploy --dry-run --outdir dist   # emits dist/index.js referenced by cloudflare.tf
```

## Apply

```bash
cd ../terraform
cp terraform.tfvars.example terraform.tfvars   # fill non-secret values
export TF_VAR_cloudflare_api_token=...          # secrets via env, not the file
export TF_VAR_origin_shared_secret=...
export TF_VAR_db_master_password=...

terraform init
terraform validate          # <-- run this: the config was authored but NOT
                            #     validated by a CLI in the authoring env
terraform plan
terraform apply
```

Then wire the outputs into the Workers and deploy them:

```bash
terraform output           # copy KV ids, queue name, hyperdrive id into the
                           # edge-firewall/ and db/consumer/ wrangler.toml files
cd ../edge-firewall && npx wrangler deploy
cd ../db/consumer   && npx wrangler deploy   # subscribes the queue consumer
```

## What Terraform owns vs. what wrangler owns

| Concern | Managed by | Why |
|---|---|---|
| KV, Queue, Hyperdrive, RDS + param group + migrations | Terraform | Stateful, auditable infra |
| Worker TS bundling + consumer queue subscription | wrangler | Build/runtime concern TF does not model |

This split is deliberate. The `cloudflare_workers_script.edge_firewall` resource
is included (the brief asks TF to provision the Worker) and references the
pre-built bundle; in practice many teams let `wrangler deploy` own the scripts and
keep TF to the durable infra. Either path works; pick one owner per resource to
avoid drift.

## Not validated in the authoring environment

`terraform`/`tofu` were not installed where this was written, so the HCL was
authored to the v4 provider schema but **not** run through `terraform validate`.
Run `terraform validate` (and a `plan`) before any `apply`. The one schema point
to watch is `cloudflare_hyperdrive_config`'s `origin`/`caching` (block vs nested
attribute) across provider patch versions — confirm against 4.52.0.
