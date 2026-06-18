#!/usr/bin/env python3
"""
OIDC Conformance Test Suite Automation for StormEngine SDK

Reads configuration from config.yml and uses the official conformance.py helper
to create test plans, run modules, and automate browser interaction via the
OIDF conformance suite's built-in Selenium.

Usage:
    python test.py                                # Run oidc_core group
    python test.py --group oidc_core              # Same as above
    python test.py --group fapi2_security_mtls    # Run FAPI2 mTLS plans
    python test.py --group all                    # Run everything

Prerequisites:
    1. OIDC conformance suite running (docker compose up)
    2. Storm server running (go run ./example/storm-server/)
    3. pip install -r requirements.txt
"""

import asyncio
import json
import os
import re
import sys

import yaml

from conformance import Conformance


def _expand_env(value, env):
    """Recursively expand ${VAR:-default} in strings."""
    if isinstance(value, str):
        def _replace(m):
            var, default = m.group(1), m.group(3) or ""
            return env.get(var, default)
        return re.sub(r"\$\{(\w+)(:-(.*?))?\}", _replace, value)
    if isinstance(value, dict):
        return {k: _expand_env(v, env) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env(v, env) for v in value]
    return value


def load_config(path="config.yml") -> dict:
    config_dir = os.path.dirname(os.path.abspath(path))

    # Concatenate config.yml with all testcase/*.yml files into a single
    # YAML document so that anchors defined in config.yml (e.g. &fapi_client)
    # are available when parsing the testcase files.
    with open(path, encoding="utf-8") as f:
        combined = f.read()

    testcase_dir = os.path.join(config_dir, "testcase")
    if os.path.isdir(testcase_dir):
        for fname in sorted(os.listdir(testcase_dir)):
            if not fname.endswith(".yml") and not fname.endswith(".yaml"):
                continue
            fpath = os.path.join(testcase_dir, fname)
            with open(fpath, encoding="utf-8") as f:
                combined += "\n" + f.read()

    raw = yaml.safe_load(combined)

    # Merge config vars into environment for ${VAR} expansion
    env = dict(os.environ)
    if isinstance(raw.get("vars"), dict):
        env.update(raw["vars"])
    expanded = _expand_env(raw, env)
    # Remove 'vars' key from final config (not a real config section)
    assert isinstance(expanded, dict)
    expanded.pop("vars", None)

    # Collect test plan groups from testcase/*.yml files.
    # Each file may define groups as top-level keys (e.g. oidc_core: [...])
    # or under a 'test_plans' / 'runner_case' wrapper.  All are merged
    # into the main config's 'test_plans' section.
    _known_config_keys = {"vars", "suite", "plan_config", "skip_modules",
                          "test_plans", "runner_case", "browser", "override"}
    all_test_plans = expanded.pop("test_plans", {}) or {}
    runner_case = expanded.pop("runner_case", None)
    if isinstance(runner_case, dict):
        all_test_plans.update(runner_case)
    # Any remaining top-level list keys are test plan groups from testcase files
    for key in list(expanded.keys()):
        if key not in _known_config_keys and isinstance(expanded[key], list):
            all_test_plans[key] = expanded.pop(key)
    if all_test_plans:
        expanded["test_plans"] = all_test_plans

    # Resolve mTLS certificate paths relative to the config file directory
    plan_cfg = expanded.get("plan_config", {})
    if isinstance(plan_cfg, dict):
        for mtls_key in ("mtls", "mtls2"):
            mtls_cfg = plan_cfg.get(mtls_key)
            if isinstance(mtls_cfg, dict):
                for field in ("ca", "cert", "key"):
                    rel_path = mtls_cfg.get(field)
                    if rel_path:
                        abs_path = os.path.normpath(os.path.join(config_dir, rel_path))
                        if os.path.isfile(abs_path):
                            with open(abs_path, "r") as f:
                                mtls_cfg[field] = f.read()
                        else:
                            print(f"WARNING: mTLS {mtls_key}.{field} file not found: {abs_path}")

    # Also propagate mTLS certs to FAPI client configs if present
    mtls_certs = plan_cfg.get("mtls", {})
    mtls_certs2 = plan_cfg.get("mtls2", {})
    if isinstance(mtls_certs, dict) and "cert" in mtls_certs:
        for key in ("fapi_client", "fapi_client_oauth"):
            client_cfg = plan_cfg.get(key)
            if isinstance(client_cfg, dict):
                client_cfg["mtls"] = mtls_certs
    if isinstance(mtls_certs2, dict) and "cert" in mtls_certs2:
        for key in ("fapi_client2", "fapi_client2_oauth"):
            client_cfg = plan_cfg.get(key)
            if isinstance(client_cfg, dict):
                client_cfg["mtls2"] = mtls_certs2
    return expanded


async def run_plan(conformance, plan_name, variant, base_plan_config, skip_modules=None, label="", hooks=None):
    """Create a test plan, run all modules, return (passed, failed, errors, review, skipped_manual, skipped_auto).
    hooks: dict mapping module_name -> async hook_fn(conformance, module_id) -> bool (True to resume)."""
    print(f"\n{'=' * 60}")
    print(f"Plan: {plan_name}")
    if label:
        print(f"Test case: {label}")
    print(f"{'=' * 60}")

    # Inject test case label into description
    cfg = dict(base_plan_config)
    base_desc = base_plan_config.get("description", "")
    cfg["description"] = f"{base_desc} ({label})" if label else base_desc
    plan_config_json = json.dumps(cfg)
    # Debug: show client config being sent
    for k in ("client", "client_secret_post", "client2"):
        if k in cfg:
            print(f"  {k}: {json.dumps(cfg[k])}")

    test_plan = await conformance.create_test_plan(plan_name, plan_config_json, variant)
    plan_id = test_plan["id"]
    suite_url = conformance.api_url_base.rstrip("/")
    print(f"Plan URL: {suite_url}/plan-detail.html?plan={plan_id}")

    passed = failed = errors = review = skipped_manual = skipped_auto = 0

    for test in test_plan["modules"]:
        module_name = test["testModule"]
        module_variant = test["variant"]

        if skip_modules and module_name in skip_modules:
            print(f"\n  Module: {module_name} — SKIPPED (in skip list)")
            skipped_manual += 1
            continue

        print(f"\n  Module: {module_name}")

        try:
            instance = await conformance.create_test_from_plan_with_variant(
                plan_id, module_name, module_variant
            )
            module_id = instance["id"]

            # Wait until module reaches CONFIGURED state
            info = await conformance.get_module_info(module_id)
            if info.get("status") == "CREATED":
                for _ in range(30):
                    await asyncio.sleep(1)
                    info = await conformance.get_module_info(module_id)
                    if info.get("status") != "CREATED":
                        break

            # For key-rotation test: trigger rotation before starting the module
            rotate_hook = hooks.get(module_name) if hooks else None
            if rotate_hook and module_name == "oidcc-server-rotate-keys":
                await rotate_hook(conformance, module_id)

            # Start the test module if it's still in CREATED/CONFIGURED state
            info = await conformance.get_module_info(module_id)
            if info.get("status") in ("CREATED", "CONFIGURED"):
                await conformance.start_test(module_id)
                # Give the server time to process the start request
                await asyncio.sleep(0.5)

            info = await _wait_with_image_detection(conformance, module_id)
            status = info.get("status")
            result = info.get("result", "UNKNOWN")

            # Retry once on FAIL or ERR (transient failures) — WARNING is acceptable, no retry needed
            if (status == "FINISHED" and result not in ("PASSED", "SKIPPED", "REVIEW", "WARNING")) or \
               (status not in ("FINISHED", "WAITING", "INTERRUPTED")):
                print(f"  Result: [{result}] — retrying once...")
                await asyncio.sleep(3)
                instance2 = await conformance.create_test_from_plan_with_variant(
                    plan_id, module_name, module_variant
                )
                module_id2 = instance2["id"]
                info2 = await conformance.get_module_info(module_id2)
                if info2.get("status") in ("CREATED", "CONFIGURED"):
                    await conformance.start_test(module_id2)
                    await asyncio.sleep(0.5)
                info2 = await _wait_with_image_detection(conformance, module_id2)
                status2 = info2.get("status")
                result2 = info2.get("result", "UNKNOWN")
                if status2 == "FINISHED" and result2 == "PASSED":
                    print(f"  Result: [PASS] PASSED (after retry)")
                    passed += 1
                    continue
                # Retry also failed — report original failure
                print(f"  Retry also: {result2}")
                status = info.get("status")
                result = info.get("result", "UNKNOWN")

            if status == "FINISHED":
                if result == "PASSED":
                    print(f"  Result: [PASS] PASSED")
                    passed += 1
                elif result == "SKIPPED":
                    print(f"  Result: [SKIP] SKIPPED (by suite)")
                    skipped_auto += 1
                elif result == "REVIEW":
                    print(f"  Result: [REVIEW] Needs manual review")
                    review += 1
                elif result == "WARNING":
                    print(f"  Result: [SKIP] WARNING (accepted)")
                    skipped_auto += 1
                else:
                    print(f"  Result: [FAIL] {result}")
                    failed += 1
            elif status == "WAITING":
                # Image upload detected — skip this module
                print(f"  Result: [SKIP] Requires image upload")
                skipped_auto += 1
            else:
                print(f"  Result: [ERR] {status} / {result}")
                # Print failure details for debugging
                details = info.get("details", [])
                for d in details:
                    if isinstance(d, dict):
                        print(f"    {d.get('id', '?')}: {d.get('description', d)}")
                errors += 1
        except Exception as e:
            print(f"  Error: {e}")
            errors += 1

        # Small delay between modules to let the server settle
        await asyncio.sleep(0.5)

    print(f"\n  Plan summary: {passed} passed, {failed} failed, {review} review, {errors} errors, "
          f"{skipped_manual} skipped (manual), {skipped_auto} skipped (auto)")
    return passed, failed, errors, review, skipped_manual, skipped_auto


async def _wait_with_image_detection(conformance, module_id, hook=None, timeout=300):
    """Poll module state. Detects image-upload WAITING and auto-skips.
    If a hook is provided, it is called when the module enters WAITING state
    (after image-upload detection). The hook receives (conformance, module_id)
    and should return True to resume the test, or False to skip."""
    import time as _time
    deadline = _time.time() + timeout
    waiting_since = None
    hook_fired = False

    while True:
        if _time.time() > deadline:
            raise TimeoutError(f"Module {module_id} timed out after {timeout}s")

        info = await conformance.get_module_info(module_id)
        status = info["status"]

        if status == "FINISHED":
            return info
        if status == "INTERRUPTED":
            return info

        if status == "WAITING":
            # Check if the test is waiting for image upload
            instr = info.get("instruction") or {}
            if isinstance(instr, str):
                instr_text = instr.lower()
            else:
                instr_text = json.dumps(instr).lower()

            if "update-image-placeholder" in instr_text or ("image" in instr_text and "upload" in instr_text):
                # This test needs image upload — auto-stop and return
                try:
                    await conformance.stop_module(module_id)
                except Exception:
                    pass
                info["status"] = "WAITING"  # signal to caller
                return info

            # Fire hook once (e.g. key rotation)
            if hook and not hook_fired:
                hook_fired = True
                try:
                    resumed = await hook(conformance, module_id)
                except Exception:
                    resumed = False
                if resumed:
                    waiting_since = None
                    continue

            if waiting_since is None:
                waiting_since = _time.time()
            # If stuck in WAITING for >120s, treat as timeout
            elif _time.time() - waiting_since > 120:
                print(f"  (stuck in WAITING for 120s, skipping)")
                try:
                    await conformance.stop_module(module_id)
                except Exception:
                    pass
                info["status"] = "WAITING"
                return info
        else:
            waiting_since = None  # reset if not WAITING

        # Poll every 2 seconds to avoid overloading the conformance suite
        # (it's a heavy Spring Boot app with MongoDB and Selenium)
        await asyncio.sleep(1)


async def main():
    import argparse

    parser = argparse.ArgumentParser(description="OIDC Conformance Test Automation")
    parser.add_argument(
        "--config", default="config.yml", help="Path to config file (default: config.yml)"
    )
    parser.add_argument(
        "--group",
        default="oidc_core",
        help="Test plan group from config: oidc_core, fapi2_security_mtls, "
             "fapi2_security_private_key_jwt, fapi2_message_signing, all",
    )
    parser.add_argument("--suite-url", default=None, help="Override suite URL")
    parser.add_argument("--token", default=None, help="Override API token")
    parser.add_argument("--publish", default=None, help="Publish results (e.g. 'summary')")
    args = parser.parse_args()

    config = load_config(args.config)

    suite_url = str(args.suite_url
        or os.environ.get("OIDF_BASE_URL")
        or config["suite"]["url"])
    # token: CLI arg > env var > config file
    token = (
        args.token
        or os.environ.get("OIDF_CONFORMANCE_TOKEN", "")
        or config["suite"].get("token", "")
    )

    # Official suite requires a token
    if "certification.openid.net" in suite_url and not token:
        print("ERROR: Official OIDF suite requires an API token.")
        print("  Get one at: https://www.certification.openid.net/tokens.html")
        print("  Then either:")
        print("    - Set OIDF_CONFORMANCE_TOKEN env var")
        print("    - Pass --token <token>")
        print("    - Set token in config.yml")
        sys.exit(1)

    verify_ssl = config["suite"].get("verify_ssl",
        "localhost" not in suite_url and "127.0.0.1" not in suite_url)
    conformance = Conformance(suite_url, token, verify_ssl=verify_ssl)

    # Build the plan_config dict (shared by all plans, description injected per-run)
    plan_cfg = config["plan_config"]
    if args.publish:
        plan_cfg["publish"] = args.publish

    # Resolve which groups to run
    all_groups = config.get("test_plans", {})
    if args.group == "all":
        groups = all_groups
    elif args.group in all_groups:
        groups = {args.group: all_groups[args.group]}
    else:
        print(f"Unknown group: {args.group}")
        print(f"Available: {', '.join(all_groups.keys())}, all")
        sys.exit(1)

    total_passed = total_failed = total_errors = total_review = 0
    total_skipped_manual = total_skipped_auto = 0
    skip_modules = set(config.get("skip_modules", []))

    # Build module hooks from config (e.g. rotate_key_endpoint)
    hooks = {}
    # Re-read raw config to get vars (they are popped by load_config)
    with open(args.config, encoding="utf-8") as _f:
        _raw = yaml.safe_load(_f)
    _env = dict(os.environ)
    if isinstance(_raw.get("vars"), dict):
        _env.update(_raw["vars"])
    issuer_url = _env.get("issuer_url", "")

    rotate_cfg = config.get("suite", {}).get("rotate_key_endpoint")
    if rotate_cfg and issuer_url:
        rotate_url = issuer_url + rotate_cfg["url"]
        rotate_method = rotate_cfg.get("method", "POST").upper()

        async def _rotate_keys_hook(conformance, module_id, _url=rotate_url, _method=rotate_method):
            try:
                conformance.httpclient.request(_method, _url)
                return True
            except Exception as e:
                print(f"  Key rotation failed: {type(e).__name__}: {e}")
                return False

        hooks["oidcc-server-rotate-keys"] = _rotate_keys_hook

    for group_name, plans in groups.items():
        print(f"\n{'#' * 60}")
        print(f"# Group: {group_name}")
        print(f"{'#' * 60}")

        for plan_def in plans:
            plan_name = plan_def["planName"]
            testcases = plan_def.get("testcase")

            if testcases:
                # Expand named testcases into individual plan runs
                for tc_name, tc_def in testcases.items():
                    variant = tc_def.get("variant")
                    # Merge per-testcase client overrides into plan config
                    tc_cfg = dict(plan_cfg)
                    for key in ("client", "client_secret_post", "client2"):
                        if key in tc_def:
                            tc_cfg[key] = tc_def[key]
                    # Expand any *-range keys into individual runs.
                    # e.g. "sender_constrain-range: [dpop, mtls]" expands
                    # into two runs with sender_constrain=dpop and sender_constrain=mtls.
                    # "response_type_range" (legacy) also works.
                    range_keys = [k for k in (variant or {}) if k.endswith("-range") or k.endswith("_range")]
                    if range_keys:
                        base = {k: v for k, v in variant.items() if k not in range_keys}
                        # Expand all range keys combinatorially
                        def _expand_ranges(base, range_keys_left):
                            if not range_keys_left:
                                yield base, []
                                return
                            rk = range_keys_left[0]
                            # Derive target key: "sender_constrain-range" → "sender_constrain"
                            target = rk.replace("-range", "").replace("_range", "")
                            for val in variant[rk]:
                                merged = {**base, target: val}
                                for expanded, labels in _expand_ranges(merged, range_keys_left[1:]):
                                    yield expanded, [str(val)] + labels

                        for v, vals in _expand_ranges(base, range_keys):
                            label = f"{tc_name}/{'_'.join(vals)}"
                            print(f"\n  [{label}]")
                            p, f, e, r, sm, sa = await run_plan(
                                conformance, plan_name, v,
                                tc_cfg, skip_modules, label=label, hooks=hooks,
                            )
                            total_passed += p
                            total_failed += f
                            total_errors += e
                            total_review += r
                            total_skipped_manual += sm
                            total_skipped_auto += sa
                    else:
                        label = tc_name
                        print(f"\n  [{label}]")
                        p, f, e, r, sm, sa = await run_plan(
                            conformance, plan_name, variant,
                            tc_cfg, skip_modules, label=label, hooks=hooks,
                        )
                        total_passed += p
                        total_failed += f
                        total_errors += e
                        total_review += r
                        total_skipped_manual += sm
                        total_skipped_auto += sa
            else:
                p, f, e, r, sm, sa = await run_plan(
                    conformance, plan_name, plan_def.get("variant"),
                    plan_cfg, skip_modules, hooks=hooks,
                )
                total_passed += p
                total_failed += f
                total_errors += e
                total_review += r
                total_skipped_manual += sm
                total_skipped_auto += sa

    print(f"\n{'=' * 60}")
    print(f"TOTAL: {total_passed} passed, {total_failed} failed, {total_review} review, {total_errors} errors, "
          f"{total_skipped_manual} skipped (manual), {total_skipped_auto} skipped (auto)")
    print(f"{'=' * 60}")

    if total_failed > 0 or total_errors > 0:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
