"""Scan, validate, and apply the policy dictionaries using Windows tools."""

from __future__ import annotations

import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from policies import (
    ALL_POLICIES,
    DEFAULT_POLICY_VALUES,
    NET_ACCOUNTS,
    POLICY_CATEGORIES,
    POLICY_GROUPS,
    REGISTRY_KEYS,
    SECEDIT_POLICIES,
    SYSTEM_SERVICES,
)

Policy = dict[str, Any]
Operation = dict[str, Any]
_net_accounts_cache: str | None = None
_secedit_cache: dict[str, Any] | None = None


def command_text(command: list[str]) -> str:
    return subprocess.list2cmdline(command)


def run_command(command: list[str]) -> Operation:
    """Run a fixed argument list without a shell and preserve diagnostics."""
    record: Operation = {
        "command": command_text(command),
        "returncode": None,
        "stdout": "",
        "stderr": "",
    }
    try:
        result = subprocess.run(command, capture_output=True, text=True, shell=False, check=False)
    except OSError as exc:
        record["stderr"] = str(exc)
        return record
    record.update(
        returncode=result.returncode,
        stdout=result.stdout.strip(),
        stderr=result.stderr.strip(),
    )
    return record


def operation_result(
    policy: Policy,
    execution: Operation | None,
    success_message: str,
    error_message: str | None = None,
) -> Operation:
    success = bool(execution and execution["returncode"] == 0 and not error_message)
    message = success_message if success else (
        error_message
        or execution.get("stderr")
        or execution.get("stdout")
        or "Windows policy command failed."
    )
    return {
        "cis_id": policy["cis_id"],
        "policy_name": policy["name"],
        "success": success,
        "message": message,
        "command": execution.get("command", "") if execution else "",
        "returncode": execution.get("returncode") if execution else None,
        "stdout": execution.get("stdout", "") if execution else "",
        "stderr": execution.get("stderr", "") if execution else "",
    }


def validation_result(policy: Policy, message: str) -> Operation:
    return operation_result(policy, None, "", f"Validation failed: {message}")


def clear_caches() -> None:
    global _net_accounts_cache, _secedit_cache
    _net_accounts_cache = None
    _secedit_cache = None


def find_policy(cis_id: str) -> tuple[str, Policy] | None:
    for tool, policies in POLICY_GROUPS.items():
        for policy in policies:
            if policy["cis_id"] == cis_id:
                return tool, policy
    return None


def compare_value(value: Any, policy: Policy) -> bool:
    if policy.get("is_string"):
        actual = {item.strip() for item in str(value).split(",") if item.strip()}
        required = {item.strip() for item in str(policy["required"]).split(",") if item.strip()}
        return actual == required
    operator = policy.get("operator", "eq")
    if operator == "eq":
        return value == policy["required"]
    if operator == "gte":
        return value >= policy["required"]
    if operator == "lte":
        return value <= policy["required"]
    if operator == "between":
        return policy["minimum"] <= value <= policy["maximum"]
    raise ValueError(f"Unsupported operator: {operator}")


def display_value(value: Any | None, policy: Policy) -> str:
    if value is None:
        return "Not Installed" if policy.get("allow_missing") else "Unavailable"
    displayed = policy.get("display", {}).get(value, policy.get("display_fallback", value))
    return f"{displayed}{policy.get('unit', '')}"


def result_for(policy: Policy, value: Any | None) -> dict[str, Any]:
    missing_allowed = value is None and policy.get("allow_missing")
    compliant = value is not None and compare_value(value, policy)
    current = (
        ("Yes" if compliant else "No")
        if policy.get("current_as_compliance")
        else display_value(value, policy)
    )
    return {
        "cis_id": policy["cis_id"],
        "name": policy["name"],
        "current": current,
        "current_raw": value,
        "required_raw": policy["required"],
        "required": (
            "Disabled or Not Installed"
            if policy.get("allow_missing") and policy.get("required") == 4
            else policy.get("target_display", display_value(policy["required"], policy))
        ),
        "status": "PASS" if missing_allowed else "ERROR" if value is None else "PASS" if compliant else "FAIL",
        "input_min": policy.get("input_min", 0),
        "input_max": policy.get("input_max", 99999),
        "is_boolean": set(policy.get("display", {})) == {0, 1},
        "input_options": policy.get("display", {}),
        "editable": policy.get("editable", True),
    }


def read_net_accounts() -> str | None:
    global _net_accounts_cache
    if _net_accounts_cache is not None:
        return _net_accounts_cache
    execution = run_command(["net", "accounts"])
    if execution["returncode"] != 0:
        return None
    _net_accounts_cache = execution["stdout"]
    return _net_accounts_cache


def parse_net_value(label: str, output: str) -> int | None:
    match = re.search(rf"{re.escape(label)}:\s+([^\r\n]+)", output, re.IGNORECASE)
    if not match:
        return None
    raw = match.group(1).strip()
    if raw.lower() in {"never", "none"}:
        return 0
    number = re.search(r"\d+", raw)
    return int(number.group()) if number else None


def current_net_values() -> dict[str, int | None]:
    output = read_net_accounts()
    return {
        policy["command"]: None if output is None else parse_net_value(policy["label"], output)
        for policy in NET_ACCOUNTS
    }


def scan_net_accounts() -> list[dict[str, Any]]:
    values = current_net_values()
    return [result_for(policy, values[policy["command"]]) for policy in NET_ACCOUNTS]


def export_secedit_policy() -> dict[str, Any] | None:
    global _secedit_cache
    if _secedit_cache is not None:
        return _secedit_cache
    with tempfile.TemporaryDirectory() as temp_dir:
        cfg_path = Path(temp_dir) / "security-policy.inf"
        execution = run_command(["secedit", "/export", "/cfg", str(cfg_path), "/quiet"])
        if execution["returncode"] != 0 or not cfg_path.exists():
            return None
        settings: dict[str, Any] = {}
        for line in cfg_path.read_text(encoding="utf-16", errors="ignore").splitlines():
            if "=" not in line:
                continue
            key, raw = (part.strip() for part in line.split("=", 1))
            if re.fullmatch(r"-?\d+", raw):
                settings[key] = int(raw)
            else:
                settings[key] = raw
        _secedit_cache = settings
        return settings


def scan_secedit_policies() -> list[dict[str, Any]]:
    settings = export_secedit_policy()
    return [
        result_for(policy, None if settings is None else settings.get(policy["key"], policy.get("missing_value")))
        for policy in SECEDIT_POLICIES
    ]


def read_registry_value(policy: Policy) -> Any | None:
    execution = run_command(["reg", "query", policy["path"], "/v", policy["value_name"]])
    if execution["returncode"] != 0:
        return policy.get("missing_value")
    if policy.get("value_type") == "REG_SZ":
        match = re.search(rf"{re.escape(policy['value_name'])}\s+REG_SZ\s+(.+)", execution["stdout"], re.IGNORECASE)
        return match.group(1).strip() if match else None
    match = re.search(rf"{re.escape(policy['value_name'])}\s+REG_DWORD\s+0x([0-9a-f]+)", execution["stdout"], re.IGNORECASE)
    return int(match.group(1), 16) if match else None


def scan_registry() -> list[dict[str, Any]]:
    return [result_for(policy, read_registry_value(policy)) for policy in REGISTRY_KEYS]


def read_service_start_type(policy: Policy) -> int | None:
    execution = run_command(["sc.exe", "qc", policy["service_name"]])
    if execution["returncode"] != 0:
        return None
    match = re.search(r"START_TYPE\s+:\s+(\d+)", execution["stdout"], re.IGNORECASE)
    return int(match.group(1)) if match else None


def scan_services() -> list[dict[str, Any]]:
    return [result_for({**policy, "editable": False}, read_service_start_type(policy)) for policy in SYSTEM_SERVICES]


def scan_all(configured_values: dict[str, int] | None = None) -> list[dict[str, Any]]:
    clear_caches()
    results = scan_net_accounts() + scan_secedit_policies() + scan_registry() + scan_services()
    for result in results:
        policy = find_policy(result["cis_id"])[1]
        configured = (configured_values or {}).get(result["cis_id"], policy["required"])
        result["configured"] = display_value(configured, policy)
        if configured_values and result["cis_id"] in configured_values and result["current_raw"] is not None:
            custom_policy = {**policy, "required": configured}
            passed = (
                result["current_raw"] == configured
                if policy.get("operator") == "between"
                else compare_value(result["current_raw"], custom_policy)
            )
            result["status"] = "PASS" if passed else "FAIL"
    return results


def validate_policy_value(policy: Policy, value: Any) -> tuple[bool, int | str]:
    if value is None or isinstance(value, str) and not value.strip():
        return False, "A value is required."
    if policy.get("value_type") == "REG_SZ" or policy.get("is_string"):
        return True, str(value)
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return False, "Value must be a whole number."
    minimum = int(policy.get("input_min", 0))
    maximum = int(policy.get("input_max", 99999))
    if not minimum <= parsed <= maximum:
        return False, f"Value must be between {minimum} and {maximum}."
    return True, parsed


def validate_net_dependencies(targets: dict[str, int]) -> str | None:
    current = current_net_values()
    merged = {key: value for key, value in current.items() if value is not None}
    merged.update(targets)
    min_age, max_age = merged.get("minpwage"), merged.get("maxpwage")
    if min_age is not None and max_age not in (None, 0) and min_age > max_age:
        return f"Minimum password age ({min_age}) cannot exceed maximum password age ({max_age})."
    duration, window = merged.get("lockoutduration"), merged.get("lockoutwindow")
    threshold = merged.get("lockoutthreshold")
    if threshold and duration is not None and window is not None and window > duration:
        return f"Lockout observation window ({window}) cannot exceed lockout duration ({duration})."
    return None


def apply_net_group(items: list[tuple[Policy, int]]) -> list[Operation]:
    global _net_accounts_cache
    targets = {policy["command"]: value for policy, value in items}
    dependency_error = validate_net_dependencies(targets)
    if dependency_error:
        return [validation_result(policy, dependency_error) for policy, _ in items]
    command = ["net", "accounts", *(f"/{policy['command']}:{value}" for policy, value in items)]
    execution = run_command(command)
    _net_accounts_cache = None
    return [
        operation_result(
            policy,
            execution,
            f"{policy['name']} set to {display_value(value, policy)}.",
        )
        for policy, value in items
    ]


def apply_secedit(policy: Policy, value: Any) -> Operation:
    with tempfile.TemporaryDirectory() as temp_dir:
        cfg_path = Path(temp_dir) / "security-policy.inf"
        db_path = Path(temp_dir) / "security-policy.sdb"
        section = "Privilege Rights" if policy.get("is_string") else "System Access"
        area = "USER_RIGHTS" if policy.get("is_string") else "SECURITYPOLICY"
        lines = ["[Unicode]", "Unicode=yes", "[Version]", 'signature=\"$CHICAGO$\"', "Revision=1", f"[{section}]"]
        # Configure only this setting. Re-exporting and writing a complete
        # section can restore stale values changed earlier in a bulk operation.
        lines.append(f"{policy['key']} = {value}")
        cfg_path.write_text("\n".join(lines) + "\n", encoding="utf-16")
        execution = run_command([
            "secedit", "/configure", "/db", str(db_path), "/cfg", str(cfg_path),
            "/areas", area, "/quiet",
        ])
    global _secedit_cache
    _secedit_cache = None
    return operation_result(policy, execution, f"{policy['name']} set to {display_value(value, policy)}.")


def apply_registry(policy: Policy, value: Any) -> Operation:
    execution = run_command([
        "reg", "add", policy["path"], "/v", policy["value_name"],
        "/t", policy.get("value_type", "REG_DWORD"), "/d", str(value), "/f",
    ])
    return operation_result(policy, execution, f"{policy['name']} set to {display_value(value, policy)}.")


def service_start_value(value: int) -> str:
    return {2: "auto", 3: "demand", 4: "disabled"}.get(value, str(value))


def apply_service(policy: Policy, value: int) -> Operation:
    current = read_service_start_type(policy)
    if current is None and policy.get("allow_missing"):
        return {
            "cis_id": policy["cis_id"],
            "policy_name": policy["name"],
            "success": True,
            "message": f"{policy['name']} is not installed.",
            "command": command_text(["sc.exe", "qc", policy["service_name"]]),
            "returncode": 0,
            "stdout": "",
            "stderr": "",
        }
    execution = run_command(["sc.exe", "config", policy["service_name"], "start=", service_start_value(value)])
    return operation_result(policy, execution, f"{policy['name']} set to {display_value(value, policy)}.")


def apply_policy(cis_id: str, value: Any = None, validate: bool = True) -> Operation:
    found = find_policy(cis_id)
    if found is None:
        return {
            "cis_id": cis_id, "policy_name": "Unknown policy", "success": False,
            "message": f"Unknown CIS control: {cis_id}", "command": "",
            "returncode": None, "stdout": "", "stderr": "",
        }
    tool, policy = found
    target = policy["required"] if value is None else value
    if validate:
        valid, parsed = validate_policy_value(policy, target)
        if not valid:
            return validation_result(policy, str(parsed))
    else:
        if policy.get("value_type") == "REG_SZ" or policy.get("is_string"):
            parsed = str(target)
        else:
            try:
                parsed = int(target)
            except (TypeError, ValueError):
                return validation_result(policy, "The configured default is not a whole number.")
    if tool == "net_accounts":
        return apply_net_group([(policy, int(parsed))])[0]
    if tool == "secedit":
        return apply_secedit(policy, parsed)
    if tool == "registry":
        return apply_registry(policy, parsed)
    return apply_service(policy, int(parsed))


def reset_policy(cis_id: str) -> Operation:
    return apply_policy(cis_id, DEFAULT_POLICY_VALUES.get(cis_id), validate=False)


def apply_policies(
    cis_ids: list[str],
    values: dict[str, Any] | None = None,
    validate: bool = True,
) -> list[Operation]:
    values = values or {}
    prepared: list[tuple[str, Policy, Any]] = []
    results: list[Operation] = []
    for cis_id in cis_ids:
        found = find_policy(cis_id)
        if found is None:
            results.append(apply_policy(cis_id))
            continue
        tool, policy = found
        target = values.get(cis_id, policy["required"])
        if validate:
            valid, parsed = validate_policy_value(policy, target)
            if not valid:
                results.append(validation_result(policy, str(parsed)))
                continue
        else:
            if policy.get("value_type") == "REG_SZ" or policy.get("is_string"):
                parsed = str(target)
            else:
                try:
                    parsed = int(target)
                except (TypeError, ValueError):
                    results.append(validation_result(policy, "The configured default is not a whole number."))
                    continue
        prepared.append((tool, policy, parsed))
    net_items = [(policy, value) for tool, policy, value in prepared if tool == "net_accounts"]
    if net_items:
        results.extend(apply_net_group(net_items))
    for tool, policy, value in prepared:
        if tool == "secedit":
            results.append(apply_secedit(policy, value))
        elif tool == "registry":
            results.append(apply_registry(policy, value))
        elif tool == "services":
            results.append(apply_service(policy, value))
    return results


def reset_all_policies() -> list[Operation]:
    return apply_policies(list(DEFAULT_POLICY_VALUES), DEFAULT_POLICY_VALUES, validate=False)


def verify_policy_values(expected: dict[str, int]) -> dict[str, int | None]:
    """Return exact value mismatches after an apply/reset operation."""
    results = scan_all()
    actual = {result["cis_id"]: result["current_raw"] for result in results}
    mismatches = {}
    for cis_id, value in expected.items():
        found = find_policy(cis_id)
        if found is not None and found[0] == "services" and actual.get(cis_id) is None and found[1].get("allow_missing"):
            continue
        matches = (
            compare_value(actual.get(cis_id), {**found[1], "required": value})
            if found is not None and actual.get(cis_id) is not None
            else actual.get(cis_id) == value
        )
        if not matches:
            mismatches[cis_id] = actual.get(cis_id)
    return mismatches


def category_ids(category: str) -> list[str]:
    return [policy["cis_id"] for policy in POLICY_CATEGORIES.get(category, [])]
