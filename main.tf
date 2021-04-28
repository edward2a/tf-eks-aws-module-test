terraform {
  required_version = ">= 0.12.0"
}

# ===============================================================================
# Variables
# ===============================================================================

variable "map_roles" {
  type = list(object({
    rolearn  = string
    username = string
    groups   = list(string)
  }))
  default = []
}

variable "map_users" {
  type = list(object({
    userarn  = string
    username = string
    groups   = list(string)
  }))
  default = []
}

variable "map_accounts" {
  type    = list(string)
  default = []
}

variable "region" {
  type    = string
  default = "eu-west-1"
}

# ===============================================================================
# ?
# ===============================================================================

provider "aws" {
  version = ">= 3.0.0"
  region  = var.region
}

# ===============================================================================
# ?
# ===============================================================================

resource "random_string" "suffix" {
  length  = 8
  special = false
}

locals {
  cluster_name = "test-eks-${random_string.suffix.result}"
}

data "aws_availability_zones" "available" {}


# ===============================================================================
# VPC
# ===============================================================================

module "vpc" {
  source = "github.com/terraform-aws-modules/terraform-aws-vpc?ref=v2.9.0"

  name                 = "test-vpc"
  cidr                 = "10.0.0.0/16"
  azs                  = data.aws_availability_zones.available.names
  private_subnets      = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets       = ["10.0.4.0/24", "10.0.5.0/24", "10.0.6.0/24"]
  enable_nat_gateway   = true
  single_nat_gateway   = true
  enable_dns_hostnames = true

  public_subnet_tags = {
    "kubernetes.io/cluster/${local.cluster_name}" = "shared"
    "kubernetes.io/role/elb"                      = "1"
  }

  private_subnet_tags = {
    "kubernetes.io/cluster/${local.cluster_name}" = "shared"
    "kubernetes.io/role/internal-elb"             = "1"
  }
}

resource "aws_security_group" "all_worker_mgmt" {
  name_prefix = "all_worker_management"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port = 22
    to_port   = 22
    protocol  = "tcp"
    cidr_blocks = [
      "10.0.0.0/8",
      "172.16.0.0/12",
      "192.168.0.0/16"
    ]
  }

  ingress {
    from_port = 0
    to_port   = 0
    protocol  = -1
    self      = true
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = -1
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ===============================================================================
# Cluster
# ===============================================================================
module aws_eks {
  source = "github.com/terraform-aws-modules/terraform-aws-eks?ref=v9.0.0"

  cluster_name    = local.cluster_name
  cluster_version = "1.18"
  vpc_id          = module.vpc.vpc_id
  subnets         = module.vpc.private_subnets

  tags = {
    Environment = "test"
    GithubRepo  = "terraform-aws-eks"
    GithubOrg   = "terraform-aws-modules"
  }

  workers_additional_policies = [
    "arn:aws:iam::281314887130:policy/AmazonEKSClusterAutoscalerPolicy"
  ]

  worker_groups_launch_template = [
    {
      name                    = "mixed-ondemand-spot"
      override_instance_types = ["t3a.small", "t3a.medium"]
      root_encrypted          = true
      root_volume_size        = 50

      asg_min_size                             = 3
      asg_desired_capacity                     = 3
      on_demand_base_capacity                  = 1
      on_demand_percentage_above_base_capacity = 0
      asg_max_size                             = 8
      spot_instance_pools                      = 3

      cpu_credits = "standard"
      key_name    = "epp@rrm-rsa"

      kubelet_extra_args = "--node-labels=node.kubernetes.io/lifecycle=`curl -s http://169.254.169.254/latest/meta-data/instance-life-cycle`"

      tags = [
        { "key"  = "k8s.io/cluster-autoscaler/enabled",
          "value"= "TRUE",
          "propagate_at_launch": "true"},
        { "key"  = "k8s.io/cluster-autoscaler/${local.cluster_name}",
          "value"= "owned",
          "propagate_at_launch": "true"},
      ]
    },
  ]

  worker_additional_security_group_ids = [aws_security_group.all_worker_mgmt.id]
  map_roles                            = var.map_roles
  map_users                            = var.map_users
  map_accounts                         = var.map_accounts
}

# ===============================================================================

data "aws_eks_cluster" "cluster" {
  name = module.aws_eks.cluster_id
}

data "aws_eks_cluster_auth" "cluster" {
  name = module.aws_eks.cluster_id
}

provider "kubernetes" {
  host                   = data.aws_eks_cluster.cluster.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.cluster.certificate_authority.0.data)
  token                  = data.aws_eks_cluster_auth.cluster.token
}

# ===============================================================================
# OIDC Provider
# ===============================================================================
data "external" "oidc_thumbprint" {
  program = [
    "/bin/bash",
    "-c",
    "openssl s_client -servername oidc.eks.${var.region}.amazonaws.com -connect oidc.eks.${var.region}.amazonaws.com:443 2>/dev/null </dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' | openssl x509 -fingerprint -sha1 -noout | sed 's/://g' | awk -F= '{print \"{\\\"thumbprint\\\":\\\"\" $2 \"\\\"}\"}'"
  ]
}

resource "aws_iam_openid_connect_provider" "cluster" {
  url = data.aws_eks_cluster.cluster.identity.0.oidc.0.issuer
  client_id_list = ["sts.amazonaws.com"]
  thumbprint_list = [data.external.oidc_thumbprint.result.thumbprint]
}

