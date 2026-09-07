import json
import os
from datetime import datetime

# Load Configuration Files
def load_json(filepath):
    with open(filepath, 'r') as f:
        return json.load(f)

# SCIM 2.0 User Payload Generator
def build_scim_user_payload(employee, entitlements, active=True):
    return {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "externalId": employee["employee_id"],
        "userName": employee["email"],
        "name": {
            "givenName": employee["first_name"],
            "familyName": employee["last_name"]
        },
        "emails": [
            {
                "value": employee["email"],
                "primary": True
            }
        ],
        "active": active,
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
            "employeeNumber": employee["employee_id"],
            "department": employee["department"],
            "title": employee["job_title"]
        },
        "entitlements": entitlements
    }

# Segregation of Duties (SoD) Risk Evaluator
def check_sod_violations(entitlements, sod_rules):
    violations = []
    entitlement_set = set(entitlements)
    
    for rule in sod_rules["rules"]:
        toxic_pair = set(rule["toxic_pair"])
        if toxic_pair.issubset(entitlement_set):
            violations.append({
                "rule_id": rule["rule_id"],
                "rule_name": rule["name"],
                "severity": rule["severity"],
                "conflict_detected": rule["toxic_pair"],
                "description": rule["description"]
            })
    return violations

# Main Processing Loop
def process_identity_lifecycle():
    rbac_roles = load_json('config/rbac_roles.json')
    sod_matrix = load_json('config/sod_matrix.json')
    hr_events = load_json('data/hr_feed.json')

    audit_logs = []
    active_user_entitlements = {}

    print("==================================================")
    print("      ENTERPRISE IGA ENGINE PROCESSING LOGS       ")
    print("==================================================\n")

    for event in hr_events:
        emp_id = event["employee_id"]
        event_type = event["event_type"]
        job_title = event["job_title"]
        timestamp = datetime.utcnow().isoformat() + "Z"

        print(f"[*] Processing Event: {event['event_id']} | Type: {event_type} | User: {event['email']}")

        if event_type == "JOINER":
            # Provision initial entitlements based on RBAC
            assigned_entitlements = rbac_roles.get(job_title, {}).get("entitlements", [])
            active_user_entitlements[emp_id] = assigned_entitlements
            
            scim_payload = build_scim_user_payload(event, assigned_entitlements, active=True)
            sod_violations = check_sod_violations(assigned_entitlements, sod_matrix)

            log_entry = {
                "timestamp": timestamp,
                "event_id": event["event_id"],
                "action": "USER_PROVISIONED",
                "employee_id": emp_id,
                "job_title": job_title,
                "assigned_entitlements": assigned_entitlements,
                "sod_violations": sod_violations,
                "scim_payload": scim_payload
            }

        elif event_type == "MOVER":
            # Calculate entitlement delta (revoke old role, assign new role)
            old_entitlements = active_user_entitlements.get(emp_id, [])
            new_entitlements = rbac_roles.get(job_title, {}).get("entitlements", [])
            
            # Check for potential accumulation/toxic state
            accumulated_entitlements = list(set(old_entitlements + new_entitlements))
            sod_violations = check_sod_violations(accumulated_entitlements, sod_matrix)
            
            # Update state to strictly reflect new role (Zero Trust role transition)
            active_user_entitlements[emp_id] = new_entitlements
            scim_payload = build_scim_user_payload(event, new_entitlements, active=True)

            log_entry = {
                "timestamp": timestamp,
                "event_id": event["event_id"],
                "action": "USER_ROLE_TRANSITION",
                "employee_id": emp_id,
                "previous_job_title": event.get("previous_title", "Unknown"),
                "new_job_title": job_title,
                "revoked_entitlements": list(set(old_entitlements) - set(new_entitlements)),
                "granted_entitlements": list(set(new_entitlements) - set(old_entitlements)),
                "sod_violations_detected": sod_violations,
                "scim_payload": scim_payload
            }

        elif event_type == "LEAVER":
            # Immediately revoke all access
            revoked_entitlements = active_user_entitlements.pop(emp_id, [])
            scim_payload = build_scim_user_payload(event, [], active=False)

            log_entry = {
                "timestamp": timestamp,
                "event_id": event["event_id"],
                "action": "USER_DEPROVISIONED",
                "employee_id": emp_id,
                "status": "DISABLED",
                "revoked_entitlements": revoked_entitlements,
                "scim_payload": scim_payload
            }

        audit_logs.append(log_entry)

        if log_entry.get("sod_violations") or log_entry.get("sod_violations_detected"):
            print(f"  [!] CRITICAL WARNING: Segregation of Duties violation flagged!")
        else:
            print(f"  [+] Action Completed Successfully. SCIM Payload generated.")
        print("-" * 50)

    # Output results
    os.makedirs('output', exist_ok=True)
    with open('output/audit_log.json', 'w') as f:
        json.dump(audit_logs, f, indent=2)

    print("\n[✔] Execution Complete. Generated governance output saved to: output/audit_log.json")

if __name__ == "__main__":
    process_identity_lifecycle()
