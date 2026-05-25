###############################################################
# SENTINEL APEX — Production Terraform Root
# Cloud: AWS (EKS + RDS + ElastiCache + MSK)
###############################################################
terraform {
  required_version = ">= 1.7.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0, < 6.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.20, < 3.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.10, < 3.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.5, < 4.0"
    }
  }

  backend "s3" {
    bucket         = "cyberdudebivash-terraform-state"
    key            = "sentinel-apex/production/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-state-lock"
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "SENTINEL-APEX"
      Environment = "production"
      ManagedBy   = "terraform"
      Owner       = "CYBERDUDEBIVASH"
    }
  }
}

###############################################################
# VPC + Networking
###############################################################
module "networking" {
  source = "../../modules/networking"

  name               = "sentinel-apex-prod"
  vpc_cidr           = "10.0.0.0/16"
  availability_zones = ["us-east-1a", "us-east-1b", "us-east-1c"]

  private_subnet_cidrs = [
    "10.0.1.0/24",
    "10.0.2.0/24",
    "10.0.3.0/24",
  ]
  public_subnet_cidrs = [
    "10.0.101.0/24",
    "10.0.102.0/24",
    "10.0.103.0/24",
  ]
  database_subnet_cidrs = [
    "10.0.201.0/24",
    "10.0.202.0/24",
    "10.0.203.0/24",
  ]

  enable_nat_gateway     = true
  single_nat_gateway     = false  # HA: one NAT per AZ
  enable_dns_hostnames   = true
  enable_vpn_gateway     = false

  # EKS cluster tagging for subnet auto-discovery
  private_subnet_tags = {
    "kubernetes.io/role/internal-elb"                        = "1"
    "kubernetes.io/cluster/sentinel-apex-prod"               = "shared"
  }
  public_subnet_tags = {
    "kubernetes.io/role/elb"                                 = "1"
    "kubernetes.io/cluster/sentinel-apex-prod"               = "shared"
  }
}

###############################################################
# EKS Cluster
###############################################################
module "eks" {
  source = "../../modules/eks"

  cluster_name    = "sentinel-apex-prod"
  cluster_version = "1.30"

  vpc_id          = module.networking.vpc_id
  subnet_ids      = module.networking.private_subnet_ids

  # Cluster endpoint — private only (Zero Trust)
  cluster_endpoint_private_access = true
  cluster_endpoint_public_access  = true  # Set false after VPN/bastion setup
  cluster_endpoint_public_access_cidrs = var.admin_cidrs

  # Node groups
  node_groups = {
    # General workload nodes
    general = {
      instance_types = ["m6i.2xlarge", "m6a.2xlarge"]
      min_size       = 3
      max_size       = 20
      desired_size   = 5
      disk_size      = 100

      labels = {
        workload = "general"
      }
      taints = []
    }

    # AI inference nodes (memory/compute optimized)
    ai_inference = {
      instance_types = ["c6i.4xlarge", "c6a.4xlarge"]
      min_size       = 2
      max_size       = 10
      desired_size   = 2
      disk_size      = 200

      labels = {
        workload = "ai-inference"
      }
      taints = [
        {
          key    = "workload"
          value  = "ai-inference"
          effect = "NO_SCHEDULE"
        }
      ]
    }

    # Data nodes (Kafka, Qdrant, Neo4j)
    data = {
      instance_types = ["r6i.2xlarge", "r6a.2xlarge"]
      min_size       = 3
      max_size       = 10
      desired_size   = 3
      disk_size      = 500

      labels = {
        workload = "data"
      }
    }
  }

  # EKS Add-ons
  cluster_addons = {
    coredns                = { most_recent = true }
    kube-proxy             = { most_recent = true }
    vpc-cni                = { most_recent = true }
    aws-ebs-csi-driver     = { most_recent = true }
    aws-efs-csi-driver     = { most_recent = true }
  }

  # IRSA for service accounts
  enable_irsa = true

  tags = {
    "karpenter.sh/discovery" = "sentinel-apex-prod"
  }
}

###############################################################
# RDS PostgreSQL (Multi-AZ, encrypted)
###############################################################
module "rds" {
  source = "../../modules/rds"

  identifier     = "sentinel-apex-prod"
  engine         = "postgres"
  engine_version = "16.2"
  instance_class = "db.r6g.2xlarge"

  allocated_storage     = 200
  max_allocated_storage = 2000  # Auto-scaling up to 2TB
  storage_encrypted     = true
  storage_type          = "gp3"

  db_name  = "sentinel_intel"
  username = "sentinel"

  # Multi-AZ for HA
  multi_az               = true
  db_subnet_group_name   = module.networking.database_subnet_group_name
  vpc_security_group_ids = [module.networking.rds_security_group_id]

  # Backups
  backup_retention_period = 30
  backup_window           = "03:00-04:00"
  maintenance_window      = "sun:04:00-sun:05:00"

  # Read replicas for analytics
  replica_count = 2

  # Performance Insights
  performance_insights_enabled          = true
  performance_insights_retention_period = 7

  # Enhanced monitoring
  monitoring_interval = 60

  # Deletion protection
  deletion_protection = true

  parameter_group_family = "postgres16"
  parameters = [
    { name = "shared_preload_libraries",   value = "pg_stat_statements,pg_cron" },
    { name = "log_min_duration_statement", value = "1000" },
    { name = "max_connections",            value = "500" },
    { name = "work_mem",                   value = "64MB" },
  ]
}

###############################################################
# ElastiCache Redis (Cluster Mode Enabled)
###############################################################
module "redis" {
  source = "../../modules/redis"

  cluster_id             = "sentinel-apex-prod"
  description            = "SENTINEL APEX — Production Redis Cluster"
  engine_version         = "7.2"
  node_type              = "cache.r7g.xlarge"

  num_cache_clusters     = 3
  automatic_failover_enabled = true
  multi_az_enabled       = true

  subnet_group_name      = module.networking.redis_subnet_group_name
  security_group_ids     = [module.networking.redis_security_group_id]

  at_rest_encryption_enabled  = true
  transit_encryption_enabled  = true
  auth_token_enabled          = true

  # Auto-backups
  snapshot_retention_limit = 7
  snapshot_window          = "05:00-06:00"

  # Cluster mode for horizontal scaling
  cluster_mode_enabled     = true
  num_node_groups          = 3
  replicas_per_node_group  = 1
}

###############################################################
# MSK Kafka (Managed Streaming)
###############################################################
resource "aws_msk_cluster" "sentinel_apex" {
  cluster_name           = "sentinel-apex-prod"
  kafka_version          = "3.6.0"
  number_of_broker_nodes = 3

  broker_node_group_info {
    instance_type   = "kafka.m5.2xlarge"
    client_subnets  = module.networking.private_subnet_ids
    security_groups = [module.networking.kafka_security_group_id]

    storage_info {
      ebs_storage_info {
        volume_size = 1000  # GB per broker
        provisioned_throughput {
          enabled           = true
          volume_throughput = 250
        }
      }
    }
  }

  encryption_info {
    encryption_in_transit {
      client_broker = "TLS"
      in_cluster    = true
    }
    encryption_at_rest_kms_key_arn = aws_kms_key.sentinel_apex.arn
  }

  client_authentication {
    sasl {
      iam = true
    }
  }

  configuration_info {
    arn      = aws_msk_configuration.sentinel_apex.arn
    revision = 1
  }

  open_monitoring {
    prometheus {
      jmx_exporter  { enabled_in_broker = true }
      node_exporter { enabled_in_broker = true }
    }
  }

  logging_info {
    broker_logs {
      cloudwatch_logs {
        enabled   = true
        log_group = "/aws/msk/sentinel-apex-prod"
      }
    }
  }

  tags = {
    Name = "sentinel-apex-prod-kafka"
  }
}

resource "aws_msk_configuration" "sentinel_apex" {
  name              = "sentinel-apex-prod"
  kafka_versions    = ["3.6.0"]
  server_properties = <<-PROPERTIES
    auto.create.topics.enable=false
    default.replication.factor=3
    min.insync.replicas=2
    num.partitions=12
    log.retention.hours=168
    log.segment.bytes=1073741824
    compression.type=lz4
    message.max.bytes=10485760
  PROPERTIES
}

###############################################################
# KMS Key for encryption at rest
###############################################################
resource "aws_kms_key" "sentinel_apex" {
  description             = "SENTINEL APEX — Encryption at Rest"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name = "sentinel-apex-prod"
  }
}

resource "aws_kms_alias" "sentinel_apex" {
  name          = "alias/sentinel-apex-prod"
  target_key_id = aws_kms_key.sentinel_apex.key_id
}

###############################################################
# Helm: Sentinel APEX Chart
###############################################################
provider "helm" {
  kubernetes {
    host                   = module.eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args        = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
    }
  }
}

resource "helm_release" "sentinel_apex" {
  name             = "sentinel-apex"
  chart            = "../../../../helm/sentinel-apex"
  namespace        = "sentinel-apex"
  create_namespace = true
  wait             = true
  timeout          = 600

  values = [
    file("${path.module}/helm-values-override.yaml")
  ]

  set {
    name  = "global.environment"
    value = "production"
  }

  set {
    name  = "global.domain"
    value = var.domain
  }

  depends_on = [
    module.eks,
    module.rds,
    module.redis,
    aws_msk_cluster.sentinel_apex,
  ]
}

# ── Additional Production Resources ──────────────────────

# Redis ElastiCache
resource "aws_elasticache_replication_group" "sentinel_redis" {
  replication_group_id       = "sentinel-apex-redis"
  description                = "SENTINEL APEX Redis cluster"
  node_type                  = "cache.r7g.large"
  num_cache_clusters         = 3
  automatic_failover_enabled = true
  multi_az_enabled           = true
  engine_version             = "7.2"
  port                       = 6379
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true

  tags = { Name = "sentinel-apex-redis", Environment = "production" }
}

# MSK Kafka
resource "aws_msk_cluster" "sentinel_kafka" {
  cluster_name           = "sentinel-apex-kafka"
  kafka_version          = "3.6.0"
  number_of_broker_nodes = 3

  broker_node_group_info {
    instance_type = "kafka.m5.2xlarge"
    storage_info {
      ebs_storage_info { volume_size = 1000 }
    }
  }

  encryption_info {
    encryption_in_transit { client_broker = "TLS" }
    encryption_at_rest { data_volume_kms_key_id = aws_kms_key.sentinel.arn }
  }
}

# KMS Key
resource "aws_kms_key" "sentinel" {
  description             = "SENTINEL APEX encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  tags = { Name = "sentinel-apex-kms" }
}

# S3 for artifact storage
resource "aws_s3_bucket" "sentinel_artifacts" {
  bucket = "sentinel-apex-artifacts-prod"
  tags   = { Environment = "production", Classification = "restricted" }
}

resource "aws_s3_bucket_versioning" "sentinel_artifacts" {
  bucket = aws_s3_bucket.sentinel_artifacts.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "sentinel_artifacts" {
  bucket = aws_s3_bucket.sentinel_artifacts.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.sentinel.arn
    }
  }
}

# CloudWatch Log Group
resource "aws_cloudwatch_log_group" "sentinel_platform" {
  name              = "/sentinel-apex/platform"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.sentinel.arn
  tags              = { Environment = "production" }
}

# WAF WebACL
resource "aws_wafv2_web_acl" "sentinel_waf" {
  name  = "sentinel-apex-waf"
  scope = "CLOUDFRONT"

  default_action {
    allow {}
  }

  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "CommonRuleSet"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "RateLimitRule"
    priority = 2

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimit"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "sentinel-apex-waf"
    sampled_requests_enabled   = true
  }
}
