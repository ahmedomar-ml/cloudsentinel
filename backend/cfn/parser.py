"""
CloudSentinel - CloudFormation (JSON) parser

بياخد template بصيغة JSON ويطلّع Resources موحّدة.
المدعوم: S3 Bucket, EC2 SecurityGroup (+ SecurityGroupIngress المنفصل), RDS DBInstance,
IAM Policy / ManagedPolicy / Role (الـ inline policies).
أي نوع تاني بيتحط في قايمة unsupported ومابيتفحصش.

مهم: لو القيمة ديناميكية (Ref, Fn::*, {{resolve:...}}) بنعلّمها DYNAMIC ومبنخمّنش.
"""

from .model import DYNAMIC, MISSING, ParsedTemplate, Resource

MAX_RESOURCES = 500
WORLD_CIDRS = ("0.0.0.0/0", "::/0")


class TemplateError(ValueError):
    """الـ template نفسه مش صالح (مش مشكلة أمنية)."""


# ---------------------------------------------------------------- helpers

def is_dynamic(value) -> bool:
    if isinstance(value, dict) and len(value) == 1:
        key = next(iter(value))
        return key == "Ref" or key.startswith("Fn::")
    if isinstance(value, str) and value.startswith("{{resolve:"):
        return True
    return False


def norm_bool(value):
    if value is MISSING or value is DYNAMIC:
        return value
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ("true", "false"):
        return value.strip().lower() == "true"
    return DYNAMIC


def norm_int(value):
    if value is MISSING or value is DYNAMIC:
        return value
    if isinstance(value, bool):
        return DYNAMIC
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value.strip())
    return DYNAMIC


def norm_str(value):
    if value is MISSING or value is DYNAMIC:
        return value
    if isinstance(value, str) and not is_dynamic(value):
        return value
    return DYNAMIC


def _present(value):
    """MISSING لو مش مكتوبة، DYNAMIC لو مش واضحة، True لو موجودة كـ object."""
    if value is MISSING:
        return MISSING
    if is_dynamic(value) or not isinstance(value, dict):
        return DYNAMIC
    return True


def _ref_target(value):
    """بيطلّع اسم الـ resource من {"Ref": "X"} أو {"Fn::GetAtt": ["X", "GroupId"]}."""
    if isinstance(value, dict) and len(value) == 1:
        if "Ref" in value and isinstance(value["Ref"], str):
            return value["Ref"]
        if "Fn::GetAtt" in value:
            target = value["Fn::GetAtt"]
            if isinstance(target, list) and target and isinstance(target[0], str):
                return target[0]
            if isinstance(target, str):
                return target.split(".")[0]
    return None


# ------------------------------------------------------------------- S3

def _parse_bucket(logical_id, props):
    raw_block = props.get("PublicAccessBlockConfiguration", MISSING)
    if raw_block is MISSING:
        block = MISSING
    elif is_dynamic(raw_block) or not isinstance(raw_block, dict):
        block = DYNAMIC
    else:
        block = {
            key: norm_bool(raw_block.get(key, MISSING))
            for key in ("BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets")
        }

    raw_versioning = props.get("VersioningConfiguration", MISSING)
    if raw_versioning is MISSING:
        versioning = MISSING
    elif is_dynamic(raw_versioning) or not isinstance(raw_versioning, dict):
        versioning = DYNAMIC
    else:
        versioning = norm_str(raw_versioning.get("Status", MISSING))

    logging = props.get("LoggingConfiguration", MISSING)
    destination = _ref_target(logging.get("DestinationBucketName")) if isinstance(logging, dict) else None

    return Resource(
        logical_id,
        "storage",
        "AWS::S3::Bucket",
        {
            "log_destination": destination,
            "is_log_destination": False,  # بيتحدد بعد قراءة كل الـ template
            "acl": norm_str(props.get("AccessControl", MISSING)),
            "block": block,
            "encryption": _present(props.get("BucketEncryption", MISSING)),
            "versioning": versioning,
            "logging": _present(props.get("LoggingConfiguration", MISSING)),
        },
    )


# ------------------------------------------------------- Security Group

_PROTOCOL_ALIASES = {"6": "tcp", "17": "udp", "1": "icmp", "-1": "-1", "all": "-1"}


def _parse_ingress_item(item):
    if not isinstance(item, dict) or is_dynamic(item):
        return {"dynamic": True}

    raw_protocol = item.get("IpProtocol", MISSING)
    if isinstance(raw_protocol, int) and not isinstance(raw_protocol, bool):
        raw_protocol = str(raw_protocol)  # بعض الـ templates بتكتب -1 كرقم مش كنص
    protocol = norm_str(raw_protocol)
    if isinstance(protocol, str):
        protocol = protocol.strip().lower()
        protocol = _PROTOCOL_ALIASES.get(protocol, protocol)

    cidrs = [norm_str(item[key]) for key in ("CidrIp", "CidrIpv6") if key in item]

    return {
        "dynamic": False,
        "protocol": protocol,
        "from_port": norm_int(item.get("FromPort", MISSING)),
        "to_port": norm_int(item.get("ToPort", MISSING)),
        "cidrs": cidrs,
    }


def _parse_security_group(logical_id, props):
    raw = props.get("SecurityGroupIngress", MISSING)
    if raw is MISSING:
        ingress = []
    elif is_dynamic(raw) or not isinstance(raw, list):
        ingress = DYNAMIC
    else:
        ingress = [_parse_ingress_item(item) for item in raw]
    return Resource(logical_id, "firewall", "AWS::EC2::SecurityGroup", {"ingress": ingress})


# ------------------------------------------------------------------ RDS

def _parse_db_instance(logical_id, props):
    raw_password = props.get("MasterUserPassword", MISSING)
    if raw_password is MISSING:
        password = MISSING
    elif is_dynamic(raw_password):
        password = "reference"
    elif isinstance(raw_password, str) and raw_password:
        password = "literal"
    else:
        password = DYNAMIC

    derived = any(
        key in props
        for key in (
            "SourceDBInstanceIdentifier",
            "DBSnapshotIdentifier",
            "RestoreTime",
            "SourceDBClusterIdentifier",
            "DBClusterIdentifier",  # عضو في Cluster: التشفير والـ backups بتتحدد على الـ Cluster
        )
    )

    return Resource(
        logical_id,
        "database",
        "AWS::RDS::DBInstance",
        {
            "publicly_accessible": norm_bool(props.get("PubliclyAccessible", MISSING)),
            "storage_encrypted": norm_bool(props.get("StorageEncrypted", MISSING)),
            "backup_retention": norm_int(props.get("BackupRetentionPeriod", MISSING)),
            "password": password,
            "managed_password": norm_bool(props.get("ManageMasterUserPassword", MISSING)),
            "derived": derived,
        },
    )


# ------------------------------------------------------------------ IAM

def _str_list(value):
    if value is MISSING:
        return []
    if isinstance(value, str):
        return [DYNAMIC] if is_dynamic(value) else [value]
    if isinstance(value, list):
        return [item if isinstance(item, str) and not is_dynamic(item) else DYNAMIC for item in value]
    return [DYNAMIC]


def _parse_statements(document):
    unknown = [{"dynamic": True}]
    if document is MISSING or is_dynamic(document) or not isinstance(document, dict):
        return unknown
    statements = document.get("Statement", MISSING)
    if isinstance(statements, dict) and not is_dynamic(statements):
        statements = [statements]
    if not isinstance(statements, list):
        return unknown

    parsed = []
    for statement in statements:
        if not isinstance(statement, dict) or is_dynamic(statement):
            parsed.append({"dynamic": True})
            continue
        parsed.append(
            {
                "dynamic": False,
                "effect": norm_str(statement.get("Effect", MISSING)),
                "actions": _str_list(statement.get("Action", MISSING)),
                "not_action": "NotAction" in statement,
                "resources": _str_list(statement.get("Resource", MISSING)),
                "not_resource": "NotResource" in statement,
            }
        )
    return parsed


def _parse_iam(logical_id, cfn_type, props):
    if cfn_type in ("AWS::IAM::Policy", "AWS::IAM::ManagedPolicy"):
        statements = _parse_statements(props.get("PolicyDocument", MISSING))
    else:  # AWS::IAM::Role: بنفحص الـ inline policies بس
        policies = props.get("Policies", MISSING)
        if policies is MISSING:
            statements = []
        elif is_dynamic(policies) or not isinstance(policies, list):
            statements = [{"dynamic": True}]
        else:
            statements = []
            for policy in policies:
                document = policy.get("PolicyDocument", MISSING) if isinstance(policy, dict) else MISSING
                statements.extend(_parse_statements(document))
    return Resource(logical_id, "iam_policy", cfn_type, {"statements": statements})


# ------------------------------------------------- parameter defaults

def _is_true(value) -> bool:
    return str(value).strip().lower() == "true"


def _substitute_defaults(value, parameters, used):
    """بيستبدل {"Ref": Param} بالقيمة الافتراضية للـ Parameter (لو موجودة)، ويسجّل اسمه في used.
    مبنستبدلش الـ Parameters اللي NoEcho (غالبًا أسرار) ولا القوايم."""
    if isinstance(value, dict):
        if len(value) == 1 and isinstance(value.get("Ref"), str):
            name = value["Ref"]
            param = parameters.get(name)
            if isinstance(param, dict) and "Default" in param and not _is_true(param.get("NoEcho", False)):
                ptype = str(param.get("Type", "String"))
                default = param["Default"]
                is_list = ptype.startswith("List<") or ptype == "CommaDelimitedList"
                if not is_list and isinstance(default, (str, int, float, bool)):
                    used.add(name)
                    return default
            return value
        return {k: _substitute_defaults(v, parameters, used) for k, v in value.items()}
    if isinstance(value, list):
        return [_substitute_defaults(v, parameters, used) for v in value]
    return value


# ----------------------------------------------------------------- main

def parse_template(template) -> ParsedTemplate:
    if not isinstance(template, dict):
        raise TemplateError("Template must be a JSON object.")

    resources = template.get("Resources")
    if not isinstance(resources, dict) or not resources:
        raise TemplateError("Template must contain a non-empty 'Resources' object.")
    if len(resources) > MAX_RESOURCES:
        raise TemplateError(f"Template has too many resources (maximum {MAX_RESOURCES}).")

    parsed = []
    unsupported = []
    standalone_ingress = []
    parameters = template.get("Parameters", {})
    if not isinstance(parameters, dict):
        parameters = {}

    warnings = []
    if "Transform" in template:
        warnings.append(
            "The template uses a Transform (macro). Resources generated by it are not visible "
            "to this scanner and were not analyzed."
        )

    for logical_id, body in resources.items():
        # Fn::ForEach بيولّد موارد وقت النشر: مش بنوسّعه، فلازم نقول إنها ماتفحصتش
        if isinstance(logical_id, str) and logical_id.startswith("Fn::ForEach::"):
            unsupported.append(
                {
                    "logical_id": logical_id,
                    "type": "Fn::ForEach",
                    "reason": "Resources generated by this loop are not expanded and were not analyzed.",
                }
            )
            continue
        if not isinstance(body, dict) or "Type" not in body:
            raise TemplateError(f"Resource '{logical_id}' must be an object with a 'Type'.")
        cfn_type = body["Type"]
        if not isinstance(cfn_type, str):
            # مثلًا Rain::Module: مش CloudFormation عادي
            unsupported.append(
                {
                    "logical_id": logical_id,
                    "type": "non-standard Type",
                    "reason": "The Type is not a plain resource type string (for example a Rain module), so it was not analyzed.",
                }
            )
            continue
        props = body.get("Properties", {})
        if not isinstance(props, dict):
            raise TemplateError(f"'Properties' of resource '{logical_id}' must be an object.")
        used_defaults = set()
        props = _substitute_defaults(props, parameters, used_defaults)

        if cfn_type == "AWS::S3::Bucket":
            parsed.append(_parse_bucket(logical_id, props))
        elif cfn_type == "AWS::EC2::SecurityGroup":
            parsed.append(_parse_security_group(logical_id, props))
        elif cfn_type == "AWS::EC2::SecurityGroupIngress":
            standalone_ingress.append((logical_id, props, used_defaults))
        elif cfn_type == "AWS::RDS::DBInstance":
            parsed.append(_parse_db_instance(logical_id, props))
        elif cfn_type in ("AWS::IAM::Policy", "AWS::IAM::ManagedPolicy", "AWS::IAM::Role"):
            parsed.append(_parse_iam(logical_id, cfn_type, props))
        else:
            unsupported.append({"logical_id": logical_id, "type": cfn_type})
            continue
        if parsed and parsed[-1].logical_id == logical_id:
            parsed[-1].param_defaults = sorted(used_defaults)

    # قواعد الدخول المنفصلة بتتضاف للـ Security Group بتاعها
    groups = {r.logical_id: r for r in parsed if r.kind == "firewall"}
    for logical_id, props, used in standalone_ingress:
        target = groups.get(_ref_target(props.get("GroupId")))
        if target is None:
            unsupported.append(
                {
                    "logical_id": logical_id,
                    "type": "AWS::EC2::SecurityGroupIngress",
                    "reason": "Refers to a security group outside this template.",
                }
            )
        elif target.data["ingress"] is not DYNAMIC:
            target.data["ingress"].append(_parse_ingress_item(props))
            target.param_defaults = sorted(set(target.param_defaults) | used)

    # الـ bucket اللي بيستقبل access logs من bucket تاني مابيسجّلش نفسه (تصميم مقصود)
    log_targets = {r.data["log_destination"] for r in parsed if r.kind == "storage" and r.data["log_destination"]}
    for r in parsed:
        if r.kind == "storage":
            r.data["is_log_destination"] = r.logical_id in log_targets

    return ParsedTemplate(parsed, unsupported, warnings)
