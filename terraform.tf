terraform {
  required_providers {
    fw-analyzer = {
      source = "local/fw-analyzer"
    }
  }
}

provider "fw-analyzer" {}

data "fw_analyzer_analysis" "check" {
  policy_json = file("policy.json")
}

output "findings" {
  value = data.fw_analyzer_analysis.check.findings
}
