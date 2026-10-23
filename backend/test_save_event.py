
from datetime import datetime, timezone
from backend.database import security_events
event = {
    "event_id": "TEST-EVENT-001",
    "identity_id": "TEST-USER-001",
    "application": "Demo SaaS",
    "permission": "admin",
    "timestamp": datetime.now(timezone.utc),
    "synthetic": True,
}

result = security_events.insert_one(event)
print(f"Event saved successfully. ID: {result.inserted_id}")

saved_event = security_events.find_one({"event_id": "TEST-EVENT-001"})
if saved_event:
    print("Event retrieved successfully!")
    print(f"Event ID: {saved_event['event_id']}")
    print(f"Application: {saved_event['application']}")
