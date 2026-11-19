-- Zealot is on by default (it only shows for Pro organizations). Organizations whose admin has changed the AI
-- setting keep their choice; every other organization is switched on. Admins can still turn it off in Safety.
ALTER TABLE orgs ALTER COLUMN ai_enabled SET DEFAULT true;
UPDATE orgs o SET ai_enabled = true
WHERE NOT o.ai_enabled
  AND NOT EXISTS (SELECT 1 FROM audit_events a WHERE a.action = 'ai.settings.changed' AND a.target_id = o.id::text);
