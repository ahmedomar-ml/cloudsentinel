"""
Loads a CloudFormation template from text (JSON or YAML) into the same plain dict that the JSON path produces.

YAML templates use short-form intrinsic functions (!Ref, !Sub, !GetAtt ...). They are converted to the long JSON form
({"Ref": ...}, {"Fn::Sub": ...}) so that the parser and the rules see one format only.

Safety:
- yaml.SafeLoader only: no arbitrary Python objects are created.
- YAML anchors and aliases are rejected (CloudFormation does not support them, and they allow "billion laughs" input).
- Unquoted dates such as 2010-09-09 stay strings (AWSTemplateFormatVersion).
"""

import json

import yaml

from .parser import TemplateError


class _CfnLoader(yaml.SafeLoader):
    pass


# keep dates as plain strings (the default resolver would turn 2010-09-09 into a date object)
_CfnLoader.yaml_implicit_resolvers = {
    key: [(tag, regexp) for tag, regexp in resolvers if tag != "tag:yaml.org,2002:timestamp"]
    for key, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}


def _no_alias(self, parent, index):
    if self.check_event(yaml.events.AliasEvent):
        raise TemplateError("YAML anchors and aliases are not supported.")
    return yaml.SafeLoader.compose_node(self, parent, index)


_CfnLoader.compose_node = _no_alias


def _node_value(loader, node):
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node, deep=True)
    return loader.construct_mapping(node, deep=True)


def _intrinsic(loader, tag_suffix, node):
    value = _node_value(loader, node)
    if tag_suffix == "Ref":
        return {"Ref": value}
    if tag_suffix == "Condition":
        return {"Condition": value}
    if tag_suffix == "GetAtt" and isinstance(value, str):
        # !GetAtt Resource.Attribute  ->  {"Fn::GetAtt": ["Resource", "Attribute"]}
        return {"Fn::GetAtt": value.split(".", 1)}
    return {f"Fn::{tag_suffix}": value}


_CfnLoader.add_multi_constructor("!", _intrinsic)


def load_template_text(text: str):
    """Parse JSON or YAML text. Raises TemplateError if it is neither, or if it is not an object."""
    if not isinstance(text, str) or not text.strip():
        raise TemplateError("The template is empty.")
    stripped = text.lstrip("\ufeff").strip()
    data = None
    if stripped.startswith("{"):
        try:
            data = json.loads(stripped)
        except ValueError:
            data = None  # fall through: maybe YAML flow style
    if data is None:
        try:
            data = yaml.load(stripped, Loader=_CfnLoader)
        except TemplateError:
            raise
        except yaml.YAMLError as exc:
            problem = getattr(exc, "problem", None) or "syntax error"
            mark = getattr(exc, "problem_mark", None)
            where = f" (line {mark.line + 1})" if mark is not None else ""
            raise TemplateError(f"Invalid YAML/JSON: {problem}{where}.")
        except RecursionError:
            raise TemplateError("The template is nested too deeply.")
    if not isinstance(data, dict):
        raise TemplateError("Template must be a JSON or YAML object.")
    return data
