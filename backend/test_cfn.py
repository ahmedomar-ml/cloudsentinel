import json
import time

from cfn.compare import compare_scans
from cfn.parser import TemplateError
from cfn.rules import RULES
from cfn.samples import CFN_SAMPLES
from cfn.scanner import scan_template
from ground_truth import GROUND_TRUTH, as_pairs


# ------------------------------------------------------------- helpers

def tpl(**resources):
    return {"Resources": {name: body for name, body in resources.items()}}


def sg(*ingress):
    return {"Type": "AWS::EC2::SecurityGroup", "Properties": {"GroupDescription": "t", "SecurityGroupIngress": list(ingress)}}


def status_of(result, rule_id, resource_id):
    for r in result["results"]:
        if r["rule_id"] == rule_id and r["resource_id"] == resource_id:
            return r["status"]
    return None


def pairs(result, status):
    return {(r["rule_id"], r["resource_id"]) for r in result["results"] if r["status"] == status}


def raises(fn, exc):
    try:
        fn()
    except exc:
        return True
    return False


# ------------------------------------------ samples vs. hand-written truth

def test_samples_match_ground_truth():
    for sample_id, truth in GROUND_TRUTH.items():
        result = scan_template(CFN_SAMPLES[sample_id]["template"])
        assert pairs(result, "FAIL") == as_pairs(truth["FAIL"]), sample_id
        assert pairs(result, "UNKNOWN") == as_pairs(truth["UNKNOWN"]), sample_id


def test_summary_adds_up():
    for sample in CFN_SAMPLES.values():
        s = scan_template(sample["template"])["summary"]
        assert s["passed"] + s["failed"] + s["unknown"] + s["not_applicable"] == s["total_checks"]
        assert s["critical"] + s["high"] + s["medium"] + s["low"] == s["failed"]


def test_unsupported_resources_are_reported_not_scanned():
    result = scan_template(CFN_SAMPLES["insecure-stack"]["template"])
    assert result["unsupported"] == [{"logical_id": "JobQueue", "type": "AWS::SQS::Queue"}]
    assert all(r["resource_id"] != "JobQueue" for r in result["results"])


def test_results_sorted_fail_first():
    result = scan_template(CFN_SAMPLES["mixed-stack"]["template"])
    order = {"FAIL": 0, "UNKNOWN": 1, "PASS": 2, "NOT_APPLICABLE": 3}
    ranks = [order[r["status"]] for r in result["results"]]
    assert ranks == sorted(ranks)


# ------------------------------------------------------- UNKNOWN logic

def test_dynamic_cidr_is_unknown_not_pass():
    t = tpl(S=sg({"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIp": {"Ref": "Cidr"}}))
    assert status_of(scan_template(t), "SG-001", "S") == "UNKNOWN"


def test_definite_fail_wins_over_unknown():
    t = tpl(
        S=sg(
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIp": {"Ref": "Cidr"}},
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIp": "0.0.0.0/0"},
        )
    )
    assert status_of(scan_template(t), "SG-001", "S") == "FAIL"


def test_dynamic_ports_are_unknown():
    t = tpl(S=sg({"IpProtocol": "tcp", "FromPort": {"Ref": "P"}, "ToPort": {"Ref": "P"}, "CidrIp": "0.0.0.0/0"}))
    assert status_of(scan_template(t), "SG-001", "S") == "UNKNOWN"


def test_missing_encryption_on_replica_is_unknown():
    t = tpl(DB={"Type": "AWS::RDS::DBInstance", "Properties": {"SourceDBInstanceIdentifier": "primary"}})
    assert status_of(scan_template(t), "RDS-002", "DB") == "UNKNOWN"


def test_missing_encryption_on_normal_instance_fails():
    t = tpl(DB={"Type": "AWS::RDS::DBInstance", "Properties": {"Engine": "mysql"}})
    assert status_of(scan_template(t), "RDS-002", "DB") == "FAIL"


def test_missing_public_flag_is_unknown():
    t = tpl(DB={"Type": "AWS::RDS::DBInstance", "Properties": {"Engine": "mysql"}})
    assert status_of(scan_template(t), "RDS-001", "DB") == "UNKNOWN"


def test_no_password_is_not_applicable():
    t = tpl(DB={"Type": "AWS::RDS::DBInstance", "Properties": {"Engine": "mysql"}})
    assert status_of(scan_template(t), "RDS-004", "DB") == "NOT_APPLICABLE"


def test_notaction_statement_is_unknown():
    t = tpl(P={"Type": "AWS::IAM::Policy", "Properties": {"PolicyDocument": {"Statement": [
        {"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}]}}})
    assert status_of(scan_template(t), "IAM-001", "P") == "UNKNOWN"


# -------------------------------------------------- real property analysis

def test_port_range_covering_ssh_is_detected():
    t = tpl(S=sg({"IpProtocol": "tcp", "FromPort": 0, "ToPort": 1024, "CidrIp": "0.0.0.0/0"}))
    r = scan_template(t)
    assert status_of(r, "SG-001", "S") == "FAIL"
    assert status_of(r, "SG-002", "S") == "PASS"


def test_ipv6_world_is_detected():
    t = tpl(S=sg({"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIpv6": "::/0"}))
    assert status_of(scan_template(t), "SG-001", "S") == "FAIL"


def test_private_cidr_and_udp_do_not_trigger():
    t = tpl(S=sg(
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIp": "10.0.0.0/8"},
        {"IpProtocol": "udp", "FromPort": 22, "ToPort": 22, "CidrIp": "0.0.0.0/0"},
    ))
    assert status_of(scan_template(t), "SG-001", "S") == "PASS"


def test_string_values_are_normalized():
    t = tpl(
        S=sg({"IpProtocol": "tcp", "FromPort": "22", "ToPort": "22", "CidrIp": "0.0.0.0/0"}),
        DB={"Type": "AWS::RDS::DBInstance", "Properties": {"PubliclyAccessible": "true"}},
    )
    r = scan_template(t)
    assert status_of(r, "SG-001", "S") == "FAIL"
    assert status_of(r, "RDS-001", "DB") == "FAIL"


def test_all_ports_and_data_ports():
    t = tpl(S=sg({"IpProtocol": "tcp", "FromPort": 0, "ToPort": 65535, "CidrIp": "0.0.0.0/0"}))
    r = scan_template(t)
    assert status_of(r, "SG-003", "S") == "FAIL"
    assert status_of(r, "SG-004", "S") == "FAIL"


def test_standalone_ingress_is_merged_into_group():
    t = {"Resources": {
        "Group": {"Type": "AWS::EC2::SecurityGroup", "Properties": {"GroupDescription": "t"}},
        "Rule": {"Type": "AWS::EC2::SecurityGroupIngress", "Properties": {
            "GroupId": {"Fn::GetAtt": ["Group", "GroupId"]}, "IpProtocol": "tcp",
            "FromPort": 22, "ToPort": 22, "CidrIp": "0.0.0.0/0"}},
    }}
    r = scan_template(t)
    assert status_of(r, "SG-001", "Group") == "FAIL"
    assert r["unsupported"] == []


def test_standalone_ingress_for_unknown_group_is_reported():
    t = {"Resources": {
        "Rule": {"Type": "AWS::EC2::SecurityGroupIngress", "Properties": {"GroupId": "sg-123"}},
        "B": {"Type": "AWS::S3::Bucket", "Properties": {}},
    }}
    assert scan_template(t)["unsupported"][0]["logical_id"] == "Rule"


def test_public_read_write_is_critical():
    t = tpl(B={"Type": "AWS::S3::Bucket", "Properties": {"AccessControl": "PublicReadWrite"}})
    result = scan_template(t)
    item = next(r for r in result["results"] if r["rule_id"] == "S3-001")
    assert item["status"] == "FAIL" and item["severity"] == "CRITICAL"


def test_iam_wildcards():
    t = tpl(
        A={"Type": "AWS::IAM::Policy", "Properties": {"PolicyDocument": {"Statement": {"Effect": "Allow", "Action": ["*"], "Resource": ["*"]}}}},
        B={"Type": "AWS::IAM::Policy", "Properties": {"PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]}}},
        C={"Type": "AWS::IAM::Policy", "Properties": {"PolicyDocument": {"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}}},
    )
    r = scan_template(t)
    assert status_of(r, "IAM-001", "A") == "FAIL"
    assert status_of(r, "IAM-001", "B") == "PASS"
    assert status_of(r, "IAM-002", "B") == "FAIL"
    assert next(x for x in r["results"] if x["rule_id"] == "IAM-002" and x["resource_id"] == "B")["severity"] == "HIGH"
    assert status_of(r, "IAM-001", "C") == "PASS"


# ----------------------------------------------------- safety / validation

def test_password_value_never_appears_in_output():
    result = scan_template(CFN_SAMPLES["insecure-stack"]["template"])
    assert "SuperSecret123!" not in json.dumps(result)
    assert status_of(result, "RDS-004", "AppDatabase") == "FAIL"


def test_invalid_templates_raise_template_error():
    assert raises(lambda: scan_template([]), TemplateError)
    assert raises(lambda: scan_template({}), TemplateError)
    assert raises(lambda: scan_template({"Resources": {}}), TemplateError)
    assert raises(lambda: scan_template({"Resources": {"X": {"Properties": {}}}}), TemplateError)
    assert raises(lambda: scan_template({"Resources": {"X": {"Type": "AWS::S3::Bucket", "Properties": []}}}), TemplateError)
    big = {"Resources": {f"R{i}": {"Type": "AWS::SQS::Queue"} for i in range(501)}}
    assert raises(lambda: scan_template(big), TemplateError)


def test_garbage_values_do_not_crash():
    t = tpl(
        S=sg("not-a-dict", {"IpProtocol": None, "CidrIp": 5}, {"dynamic": True}),
        B={"Type": "AWS::S3::Bucket", "Properties": {"PublicAccessBlockConfiguration": "x", "VersioningConfiguration": 3}},
        P={"Type": "AWS::IAM::Policy", "Properties": {"PolicyDocument": "oops"}},
    )
    result = scan_template(t)
    assert result["summary"]["total_checks"] > 0


# ------------------------------------- constructs found in real templates

def test_foreach_is_reported_not_rejected():
    t = {"Resources": {
        "Fn::ForEach::Buckets": ["Id", ["A", "B"], {"Bucket${Id}": {"Type": "AWS::S3::Bucket", "Properties": {}}}],
        "Queue": {"Type": "AWS::SQS::Queue"},
    }}
    r = scan_template(t)
    assert any(u["type"] == "Fn::ForEach" for u in r["unsupported"])
    assert "not expanded" in r["unsupported"][0]["reason"]


def test_non_string_type_is_reported_not_rejected():
    t = {"Resources": {
        "Net": {"Type": {"Rain::Module": "vpc.yml"}, "Properties": {"Name": "x"}},
        "B": {"Type": "AWS::S3::Bucket", "Properties": {}},
    }}
    r = scan_template(t)
    assert r["summary"]["resources_analyzed"] == 1
    assert r["unsupported"][0]["logical_id"] == "Net"


def test_transform_adds_a_warning():
    t = {"Transform": "AWS::Serverless-2016-10-31", "Resources": {"B": {"Type": "AWS::S3::Bucket", "Properties": {}}}}
    r = scan_template(t)
    assert len(r["warnings"]) == 1 and "Transform" in r["warnings"][0]
    assert scan_template({"Resources": {"B": {"Type": "AWS::S3::Bucket"}}})["warnings"] == []


# ------------- regressions found by scanning AWS's real sample templates

def test_numeric_ip_protocol_minus_one_is_detected():
    # ECS/EC2LaunchType/clusters/public-vpc.json بيكتب "IpProtocol": -1 كرقم
    t = tpl(S=sg({"CidrIp": "0.0.0.0/0", "IpProtocol": -1}))
    r = scan_template(t)
    assert status_of(r, "SG-003", "S") == "FAIL"
    assert status_of(r, "SG-001", "S") == "FAIL"


def test_aurora_cluster_member_is_not_flagged_as_unencrypted():
    # DMS/DMSAuroraToS3...json: DBInstance عضو في cluster، والتشفير بيتحدد على الـ cluster
    t = tpl(DB={"Type": "AWS::RDS::DBInstance", "Properties": {
        "DBClusterIdentifier": {"Ref": "AuroraCluster"}, "Engine": "aurora-postgresql", "PubliclyAccessible": False}})
    r = scan_template(t)
    assert status_of(r, "RDS-002", "DB") == "UNKNOWN"
    assert status_of(r, "RDS-003", "DB") == "UNKNOWN"
    assert status_of(r, "RDS-001", "DB") == "PASS"   # الفحوصات اللي بتخص الـ instance لسه شغالة


def test_log_destination_bucket_is_not_required_to_log_itself():
    # S3/compliant-bucket.json: الـ log bucket مابيسجّلش نفسه
    t = tpl(
        Data={"Type": "AWS::S3::Bucket", "Properties": {"LoggingConfiguration": {"DestinationBucketName": {"Ref": "Logs"}}}},
        Logs={"Type": "AWS::S3::Bucket", "Properties": {}},
        Other={"Type": "AWS::S3::Bucket", "Properties": {}},
    )
    r = scan_template(t)
    assert status_of(r, "S3-005", "Data") == "PASS"
    assert status_of(r, "S3-005", "Logs") == "NOT_APPLICABLE"
    assert status_of(r, "S3-005", "Other") == "FAIL"      # bucket عادي لازم يفضل يتفحص


def test_parameter_default_is_used_and_reported():
    t = {
        "Parameters": {"SSHLocation": {"Type": "String", "Default": "0.0.0.0/0"}},
        "Resources": {"S": sg({"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIp": {"Ref": "SSHLocation"}})},
    }
    r = scan_template(t)
    item = next(x for x in r["results"] if x["rule_id"] == "SG-001")
    assert item["status"] == "FAIL"
    assert item["depends_on_parameter_defaults"] == ["SSHLocation"]


def test_parameter_without_default_stays_unknown():
    t = {
        "Parameters": {"SSHLocation": {"Type": "String"}},
        "Resources": {"S": sg({"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIp": {"Ref": "SSHLocation"}})},
    }
    r = scan_template(t)
    item = next(x for x in r["results"] if x["rule_id"] == "SG-001")
    assert item["status"] == "UNKNOWN" and item["depends_on_parameter_defaults"] == []


def test_noecho_parameter_default_is_never_substituted():
    # لو استبدلناه هيبان كأنه password مكتوب في الـ template
    t = {
        "Parameters": {"Pw": {"Type": "String", "NoEcho": True, "Default": "changeme"}},
        "Resources": {"DB": {"Type": "AWS::RDS::DBInstance", "Properties": {"MasterUserPassword": {"Ref": "Pw"}}}},
    }
    r = scan_template(t)
    assert status_of(r, "RDS-004", "DB") == "PASS"
    assert "changeme" not in json.dumps(r)


def test_list_parameter_default_is_not_substituted():
    t = {
        "Parameters": {"Cidrs": {"Type": "CommaDelimitedList", "Default": "0.0.0.0/0"}},
        "Resources": {"S": sg({"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIp": {"Ref": "Cidrs"}})},
    }
    assert status_of(scan_template(t), "SG-001", "S") == "UNKNOWN"


# ---------------------------------------------------------- comparison

def test_compare_insecure_to_fixed():
    before = scan_template(CFN_SAMPLES["insecure-stack"]["template"])
    after = scan_template(CFN_SAMPLES["insecure-stack-fixed"]["template"])
    c = compare_scans(before, after)["counts"]
    assert c == {"resolved": 17, "new": 0, "unchanged": 0, "not_reevaluated": 0}


def test_compare_reverse_shows_new_findings():
    before = scan_template(CFN_SAMPLES["insecure-stack-fixed"]["template"])
    after = scan_template(CFN_SAMPLES["insecure-stack"]["template"])
    c = compare_scans(before, after)["counts"]
    assert c["new"] == 17 and c["resolved"] == 0


def test_compare_unknown_and_removed_are_not_reevaluated():
    before = scan_template(tpl(
        S=sg({"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIp": "0.0.0.0/0"}),
        B={"Type": "AWS::S3::Bucket", "Properties": {"AccessControl": "PublicRead"}},
    ))
    after = scan_template(tpl(
        S=sg({"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIp": {"Ref": "Cidr"}}),
    ))
    c = compare_scans(before, after)
    removed = {(x["rule_id"], x["resource_id"]) for x in c["not_reevaluated"]}
    assert ("SG-001", "S") in removed          # بقت UNKNOWN: مقدرناش نتأكد إنها اتصلحت
    assert ("S3-001", "B") in removed          # المورد اتشال
    assert c["counts"]["resolved"] == 0


def test_compare_unchanged():
    t = tpl(B={"Type": "AWS::S3::Bucket", "Properties": {"AccessControl": "PublicRead"}})
    c = compare_scans(scan_template(t), scan_template(t))
    # الـ bucket ده بيفشل في الـ 5 قواعد بتاعة S3، وكلهم لسه فاشلين في الفحص التاني
    assert c["counts"] == {"resolved": 0, "new": 0, "unchanged": 5, "not_reevaluated": 0}


# --------------------------------------------------------------- misc

def test_rule_ids_are_unique_and_documented():
    ids = [r.id for r in RULES]
    assert len(ids) == len(set(ids))
    for r in RULES:
        assert r.impact and r.recommendation and r.reference


def test_scan_is_fast():
    big = {"Resources": {f"B{i}": {"Type": "AWS::S3::Bucket", "Properties": {}} for i in range(300)}}
    start = time.perf_counter()
    scan_template(big)
    assert time.perf_counter() - start < 2.0
