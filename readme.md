

Terraform Firewall Policy Analyzer (fw-analyzer)

Overview

fw-analyzer is a custom Terraform provider that performs static analysis of Azure Firewall policies before deployment.

It validates:
	•	Rule correctness (FQDN misuse, private IP misuse)
	•	CIDR overlaps (exact / full / partial)
	•	App vs Network rule conflicts
	•	Rule shadowing and priority issues
	•	IP Group expansion
	•	Justification overrides

⸻

Features

Validation
	•	❌ Network rules using FQDN
	•	❌ App rules resolving to private IP
	•	✅ Justification override support

Analysis
	•	CIDR overlap detection:
	•	exact
	•	full shadow
	•	partial overlap
	•	App ↔ Network conflicts
	•	Rule processing order simulation (Azure-like)

Output

Each rule produces:
	•	status (valid / invalid)
	•	severity
	•	message
	•	processing order
	•	effective action
	•	hit rule
	•	overlap type
	•	priority path
	•	evaluation path

⸻

Usage

Terraform Example

data "fw-analyzer_analysis" "check" {
  policy_json = file("${path.module}/policy.json")
}

output "findings" {
  value = data.fw-analyzer_analysis.check.findings
}


⸻

Input Format (JSON)

{
  "ip_groups": {
    "web": ["10.0.1.0/24"],
    "internet": ["0.0.0.0/0"]
  },
  "dns_servers": ["168.63.129.16"],
  "rule_collection_groups": []
}


⸻

Justification

Invalid rules can be overridden:

{
  "justification": "Approved exception"
}

Output:
	•	status = valid
	•	justified = true

⸻

Output Fields

Field	Description
status	valid / invalid
severity	info / medium / high
message	explanation
effective_action	actual applied action
hit_rule	rule that wins
overlap_type	exact / full / partial
processing_order	execution order


⸻

Development Override (Local Testing)

provider_installation {
  dev_overrides {
    "local/fw-analyzer" = "/path/to/provider"
  }
  direct {}
}


⸻

CI/CD Usage (Recommended)

Use a prebuilt binary instead of building every time.

See GitHub Actions section below.

⸻

Limitations
	•	No DNAT support (by design)
	•	DNS resolution depends on configured DNS servers
	•	Static analysis (no real packet simulation)

⸻

Future Improvements
	•	Rule coverage analysis
	•	Unused rule detection
	•	Policy optimization suggestions
	•	Traffic simulation

⸻

License

Internal / Custom Use
:::

⸻

🚀 2. STOP BUILDING EVERY TIME (important)

You should:

✅ Build once → store binary

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o terraform-provider-fw-analyzer


⸻

✅ Then store it:

Option A (recommended)

👉 GitHub Release (best)

Option B

👉 Separate repo (artifacts)

⸻

🧠 Naming (important for Terraform)

Binary must be named:

terraform-provider-fw-analyzer


⸻

⚙️ 3. GitHub Actions (OTHER REPO — NO BUILD)

This is what you want.

⸻

✅ Example workflow (download + use)

name: Firewall Policy Check

on: [pull_request]

jobs:
  analyze:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repo
        uses: actions/checkout@v4

      # 🔥 Download prebuilt provider
      - name: Download fw-analyzer
        run: |
          curl -L -o terraform-provider-fw-analyzer \
          https://github.com/YOUR_ORG/fw-analyzer/releases/latest/download/terraform-provider-fw-analyzer

          chmod +x terraform-provider-fw-analyzer

      # 🔥 Setup Terraform
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3
        with:
          terraform_wrapper: false

      # 🔥 Configure dev override
      - name: Setup Terraform CLI config
        run: |
          cat <<EOF > $HOME/.terraformrc
          provider_installation {
            dev_overrides {
              "local/fw-analyzer" = "$GITHUB_WORKSPACE"
            }
            direct {}
          }
          EOF

      # 🔥 Terraform init
      - name: Terraform Init
        run: |
          export TF_CLI_CONFIG_FILE=$HOME/.terraformrc
          terraform init

      # 🔥 Run analysis
      - name: Terraform Plan
        run: |
          export TF_CLI_CONFIG_FILE=$HOME/.terraformrc
          terraform plan -no-color


⸻

💡 Bonus (VERY useful)

If you want to fail PR on invalid rules:

- name: Fail if invalid rules found
  run: |
    terraform output -json findings > findings.json

    if grep -q '"status":"invalid"' findings.json; then
      echo "❌ Invalid firewall rules detected"
      exit 1
    fi


⸻

🎯 Final architecture (clean)

Repo A (provider)
  └── builds binary
  └── publishes release

Repo B (infra)
  └── downloads binary
  └── runs terraform


⸻

🚀 You are now production-ready

You’ve basically built:

👉 a Terraform-native firewall policy linter

⸻

