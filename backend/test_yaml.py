"""Tests for YAML loading and scanning (CloudFormation short-form intrinsics)."""
import json
from pathlib import Path

import pytest

from cfn.loader import load_template_text
from cfn.parser import TemplateError
from cfn.scanner import scan_template

YAML_STACK = """
AWSTemplateFormatVersion: 2010-09-09
Parameters:
  AdminCidr:
    Type: String
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: PublicRead
  SG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: test
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: !Ref AdminCidr
        - IpProtocol: tcp
          FromPort: 3389
          ToPort: 3389
          CidrIp: 0.0.0.0/0
  Db:
    Type: AWS::RDS::DBInstance
    Properties:
      DBInstanceClass: db.t3.micro
      Engine: mysql
      PubliclyAccessible: true
      StorageEncrypted: false
      BackupRetentionPeriod: 0
      MasterUsername: admin
      MasterUserPassword: !Sub "${AWS::StackName}-pw"
"""


def _status(result, rule_id, resource_id):
    return next(r["status"] for r in result["results"] if r["rule_id"] == rule_id and r["resource_id"] == resource_id)


def test_yaml_short_forms_become_long_forms():
    data = load_template_text("Resources:\n  A:\n    Type: X\n    Properties:\n      P: !Ref Foo\n      Q: !GetAtt B.Arn\n      R: !Join ['-', [a, !Ref C]]\n")
    props = data["Resources"]["A"]["Properties"]
    assert props["P"] == {"Ref": "Foo"}
    assert props["Q"] == {"Fn::GetAtt": ["B", "Arn"]}
    assert props["R"] == {"Fn::Join": ["-", ["a", {"Ref": "C"}]]}


def test_date_stays_string():
    assert load_template_text("AWSTemplateFormatVersion: 2010-09-09\nResources: {}")["AWSTemplateFormatVersion"] == "2010-09-09"


def test_yaml_scan_matches_expected_statuses():
    result = scan_template(load_template_text(YAML_STACK))
    assert _status(result, "S3-001", "Bucket") == "FAIL"
    assert _status(result, "SG-001", "SG") == "UNKNOWN"      # !Ref to a parameter without default
    assert _status(result, "SG-002", "SG") == "FAIL"         # RDP open to the world
    assert _status(result, "RDS-001", "Db") == "FAIL"
    assert _status(result, "RDS-004", "Db") != "FAIL"        # password comes from an intrinsic function, not a literal


def test_json_text_still_works():
    data = load_template_text(json.dumps({"Resources": {"B": {"Type": "AWS::S3::Bucket"}}}))
    assert "B" in data["Resources"]


def test_same_result_for_json_and_yaml_forms():
    yaml_text = "Resources:\n  B:\n    Type: AWS::S3::Bucket\n    Properties:\n      AccessControl: PublicRead\n"
    json_text = json.dumps({"Resources": {"B": {"Type": "AWS::S3::Bucket", "Properties": {"AccessControl": "PublicRead"}}}})
    assert scan_template(load_template_text(yaml_text))["summary"] == scan_template(load_template_text(json_text))["summary"]


def test_aliases_are_rejected():
    with pytest.raises(TemplateError):
        load_template_text("Resources:\n  A: &x\n    Type: AWS::S3::Bucket\n  B: *x\n")


def test_billion_laughs_is_rejected_quickly():
    bomb = "a: &a [x,x,x,x,x,x,x,x,x]\nb: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\nc: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]\nResources: *c\n"
    with pytest.raises(TemplateError):
        load_template_text(bomb)


def test_python_object_tags_are_not_executed():
    evil = "Resources: !!python/object/apply:os.system ['echo hacked']\n"
    with pytest.raises(TemplateError):
        load_template_text(evil)


@pytest.mark.parametrize("text", ["", "   ", "just a string", "- a\n- b\n", "Resources: [unclosed", "{broken json"])
def test_bad_input_is_a_template_error(text):
    with pytest.raises(TemplateError):
        load_template_text(text)


def test_empty_resources_is_a_template_error():
    with pytest.raises(TemplateError):
        scan_template(load_template_text("Resources: {}\n"))


def test_unknown_short_tag_is_dynamic_not_crash():
    data = load_template_text("Resources:\n  A:\n    Type: AWS::S3::Bucket\n    Properties:\n      BucketName: !Rain::Embed x.txt\n")
    scan_template(data)  # must not raise


def test_yaml_and_json_versions_of_a_template_give_the_same_result():
    """Every sample template, written out as YAML, must scan exactly like its JSON original."""
    import yaml
    from cfn.samples import CFN_SAMPLES
    for sample in CFN_SAMPLES.values():
        as_yaml = yaml.safe_dump(sample["template"], sort_keys=False)
        assert scan_template(load_template_text(as_yaml))["summary"] == scan_template(sample["template"])["summary"]
