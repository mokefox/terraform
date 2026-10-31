"""
Unit tests for OSI Reference Model Security Auditor & Auto-Remediation Tool
Compatible with both standard unittest and pytest without external test dependencies.
"""

import os
import sys
import tempfile
import unittest

# Ensure scripts directory is in sys.path
SCRIPT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts"))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from osi_security_audit import (
    HclParser,
    HclResource,
    Finding,
    RulesConfig,
    OsiAuditor,
    RemediationManager,
    MermaidGenerator,
    ReportFormatter,
)


class TestHclParser(unittest.TestCase):
    def test_clean_content(self):
        text = """
        # Line comment 1
        // Line comment 2
        /* Block comment */
        resource "aws_vpc" "main" {
            cidr_block = "10.0.0.0/16" # inline comment
        }
        """
        cleaned = HclParser.clean_content(text)
        self.assertNotIn("# Line comment 1", cleaned)
        self.assertNotIn("// Line comment 2", cleaned)
        self.assertNotIn("Block comment", cleaned)
        self.assertIn('cidr_block = "10.0.0.0/16"', cleaned)

    def test_parse_blocks(self):
        with tempfile.NamedTemporaryFile("w", suffix=".tf", delete=False) as f:
            f.write("""
            resource "aws_vpc" "test_vpc" {
                cidr_block = "10.0.0.0/16"
                enable_dns_support = true
            }

            resource "aws_subnet" "test_subnet" {
                vpc_id = aws_vpc.test_vpc.id
                cidr_block = "10.0.1.0/24"
            }
            """)
            f_path = f.name

        try:
            resources = HclParser.parse_blocks(f_path)
            self.assertEqual(len(resources), 2)
            self.assertEqual(resources[0].type, "aws_vpc")
            self.assertEqual(resources[0].name, "test_vpc")
            self.assertEqual(resources[0].attrs.get("cidr_block"), "10.0.0.0/16")
            self.assertEqual(resources[1].type, "aws_subnet")
            self.assertEqual(resources[1].name, "test_subnet")
        finally:
            if os.path.exists(f_path):
                os.remove(f_path)


class TestRulesConfig(unittest.TestCase):
    def test_default_config(self):
        config = RulesConfig()
        self.assertTrue(config.is_enabled("L1-REGION-POLICY"))
        self.assertEqual(config.get_severity("L1-REGION-POLICY", "DEFAULT"), "DEFAULT")
        self.assertFalse(config.is_suppressed("L1-REGION-POLICY", "res"))
        self.assertIn("ap-northeast-1", config.get_setting("allowed_regions"))

    def test_custom_overrides(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write("""
            {
                "rules": {
                    "L1-REGION-POLICY": {
                        "enabled": false,
                        "severity": "LOW"
                    }
                },
                "suppressions": [
                    {
                        "check_id": "L3-NETWORK-ACL",
                        "resource": "aws_network_acl.ignored"
                    }
                ]
            }
            """)
            cfg_path = f.name

        try:
            config = RulesConfig(cfg_path)
            self.assertFalse(config.is_enabled("L1-REGION-POLICY"))
            self.assertEqual(config.get_severity("L1-REGION-POLICY", "HIGH"), "LOW")
            self.assertTrue(config.is_suppressed("L3-NETWORK-ACL", "aws_network_acl.ignored"))
            self.assertFalse(config.is_suppressed("L3-NETWORK-ACL", "aws_network_acl.other"))
        finally:
            if os.path.exists(cfg_path):
                os.remove(cfg_path)


class TestOsiAuditorLayers(unittest.TestCase):
    def setUp(self):
        self._temp_dir_obj = tempfile.TemporaryDirectory()
        self.temp_workspace = self._temp_dir_obj.name

    def tearDown(self):
        self._temp_dir_obj.cleanup()

    def test_l1_region_violation_and_remediation(self):
        tf_file = os.path.join(self.temp_workspace, "main.tf")
        with open(tf_file, "w") as f:
            f.write("""
            resource "aws_s3_bucket" "b" {
                region = "us-east-1"
            }
            """)
        auditor = OsiAuditor(self.temp_workspace)
        auditor.load_codebase()
        auditor.run_audit()

        findings = [f for f in auditor.findings if f.check_id == "L1-REGION-POLICY"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertIsNotNone(findings[0].code_remediation)
        self.assertIn('region = "ap-northeast-1"', findings[0].code_remediation)

    def test_l2_vpc_isolation(self):
        tf_file = os.path.join(self.temp_workspace, "main.tf")
        with open(tf_file, "w") as f:
            f.write("""
            resource "aws_instance" "ec2" {
                ami = "ami-123456"
            }
            """)
        auditor = OsiAuditor(self.temp_workspace)
        auditor.load_codebase()
        auditor.run_audit()

        findings = [f for f in auditor.findings if f.check_id == "L2-VPC-ISOLATION"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "CRITICAL")
        self.assertIn('resource "aws_vpc"', findings[0].code_remediation)

    def test_l3_subnet_segregation(self):
        tf_file = os.path.join(self.temp_workspace, "vpc.tf")
        with open(tf_file, "w") as f:
            f.write("""
            resource "aws_vpc" "vpc-main" {
                cidr_block = "10.0.0.0/16"
            }
            resource "aws_subnet" "public_subnet" {
                vpc_id = aws_vpc.vpc-main.id
                cidr_block = "10.0.1.0/24"
            }
            """)
        auditor = OsiAuditor(self.temp_workspace)
        auditor.load_codebase()
        auditor.run_audit()

        l3_findings = [f for f in auditor.findings if f.check_id == "L3-SUBNET-SEGREGATION"]
        self.assertEqual(len(l3_findings), 1)
        self.assertEqual(l3_findings[0].severity, "HIGH")
        self.assertIn('resource "aws_subnet" "private_subnet"', l3_findings[0].code_remediation)
        self.assertIsNotNone(l3_findings[0].diff_patch)

    def test_l4_dangerous_management_ports(self):
        tf_file = os.path.join(self.temp_workspace, "sg.tf")
        with open(tf_file, "w") as f:
            f.write("""
            resource "aws_security_group" "ssh_sg" {
                name = "ssh-sg"
            }
            resource "aws_vpc_security_group_ingress_rule" "open_ssh" {
                security_group_id = aws_security_group.ssh_sg.id
                cidr_ipv4 = "0.0.0.0/0"
                from_port = 22
                to_port = 22
                ip_protocol = "tcp"
            }
            """)
        auditor = OsiAuditor(self.temp_workspace)
        auditor.load_codebase()
        auditor.run_audit()

        findings = [f for f in auditor.findings if f.check_id == "L4-MANAGEMENT-PORTS"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "CRITICAL")

    def test_l7_waf_and_imdsv2(self):
        tf_file = os.path.join(self.temp_workspace, "app.tf")
        with open(tf_file, "w") as f:
            f.write("""
            resource "aws_lb" "alb" {
                load_balancer_type = "application"
                drop_invalid_header_fields = true
            }
            resource "aws_instance" "ec2" {
                ami = "ami-123"
            }
            """)
        auditor = OsiAuditor(self.temp_workspace)
        auditor.load_codebase()
        auditor.run_audit()

        waf_findings = [f for f in auditor.findings if f.check_id == "L7-WAF-PROTECTION"]
        self.assertEqual(len(waf_findings), 1)
        self.assertEqual(waf_findings[0].severity, "HIGH")
        self.assertIn('resource "aws_wafv2_web_acl"', waf_findings[0].code_remediation)

        imdsv2_findings = [f for f in auditor.findings if f.check_id == "L7-IMDSV2-PROTECTION"]
        self.assertEqual(len(imdsv2_findings), 1)
        self.assertEqual(imdsv2_findings[0].severity, "CRITICAL")
        self.assertIn('http_tokens', imdsv2_findings[0].code_remediation)
        self.assertIn('required', imdsv2_findings[0].code_remediation)


class TestRemediationManager(unittest.TestCase):
    def test_generate_unified_patch(self):
        with tempfile.NamedTemporaryFile("w", suffix=".tf", delete=False) as f:
            f.write('resource "aws_vpc" "main" {\n  cidr_block = "10.0.0.0/16"\n}\n')
            f_path = f.name

        try:
            finding = Finding(
                layer=3,
                layer_name="L3 ネットワーク層 (Network Layer)",
                check_id="L3-SUBNET-SEGREGATION",
                severity="HIGH",
                title="パブリック / プライベートサブネットの未分離",
                resource="aws_subnet",
                file_path=f_path,
                description="desc",
                recommendation="rec",
                code_remediation='resource "aws_subnet" "private" {\n  cidr_block = "10.0.2.0/24"\n}\n'
            )
            patch = RemediationManager.generate_unified_patch([finding], os.path.dirname(f_path))
            self.assertIn("--- a/", patch)
            self.assertIn("+++ b/", patch)
            self.assertIn('+resource "aws_subnet" "private"', patch)
        finally:
            if os.path.exists(f_path):
                os.remove(f_path)

    def test_apply_fixes_dry_run_and_execution(self):
        with tempfile.NamedTemporaryFile("w", suffix=".tf", delete=False) as f:
            f.write('resource "aws_vpc" "main" {\n  cidr_block = "10.0.0.0/16"\n}\n')
            f_path = f.name

        try:
            finding = Finding(
                layer=3,
                layer_name="L3 ネットワーク層 (Network Layer)",
                check_id="L3-SUBNET-SEGREGATION",
                severity="HIGH",
                title="Subnet segregation",
                resource="aws_subnet",
                file_path=f_path,
                description="desc",
                recommendation="rec",
                code_remediation='resource "aws_subnet" "private_subnet" {\n  cidr_block = "10.0.2.0/24"\n}\n'
            )

            # Dry-run
            dry_results = RemediationManager.apply_fixes([finding], dry_run=True, backup=True)
            self.assertEqual(len(dry_results["applied"]), 1)
            self.assertFalse(os.path.exists(f_path + ".bak"))
            with open(f_path, "r") as f:
                self.assertNotIn("private_subnet", f.read())

            # Real execution
            real_results = RemediationManager.apply_fixes([finding], dry_run=False, backup=True)
            self.assertEqual(len(real_results["applied"]), 1)
            self.assertTrue(os.path.exists(f_path + ".bak"))
            with open(f_path, "r") as f:
                self.assertIn("private_subnet", f.read())

            if os.path.exists(f_path + ".bak"):
                os.remove(f_path + ".bak")
        finally:
            if os.path.exists(f_path):
                os.remove(f_path)


class TestMermaidGenerator(unittest.TestCase):
    def test_mermaid_generation(self):
        sg_res = HclResource(
            kind="resource",
            type="aws_security_group",
            name="alb_sg",
            attrs={"description": "ALB SG"},
            raw_body="",
            file_path="elb.tf"
        )
        rule_res = HclResource(
            kind="resource",
            type="aws_vpc_security_group_ingress_rule",
            name="allow_https",
            attrs={
                "security_group_id": "aws_security_group.alb_sg.id",
                "cidr_ipv4": "0.0.0.0/0",
                "from_port": "443",
                "to_port": "443",
                "ip_protocol": "tcp"
            },
            raw_body="",
            file_path="elb.tf"
        )

        chart = MermaidGenerator.generate({"alb_sg": sg_res}, [rule_res])
        self.assertIn("graph TB", chart)
        self.assertIn("subgraph External", chart)
        self.assertIn('Internet -->|"TCP:443"| sg_alb_sg', chart)


if __name__ == "__main__":
    unittest.main()
