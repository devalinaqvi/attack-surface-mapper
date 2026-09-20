import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

from dam.analysis import scan


def test_schema_validates_report(demo):
    schema = json.loads(
        (Path(__file__).parents[1] / "schemas/report-1.0.0.schema.json").read_text()
    )
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    report = scan(demo, inspect_content=True)
    validator.validate(report)
    report["findings"][0]["confidence"] = "certain"
    with pytest.raises(ValidationError):
        validator.validate(report)
