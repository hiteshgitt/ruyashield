-- Multi-turn AI chat on a finding. Each turn is an ordinary ai_analyses row (use_case 'chat'), so it keeps the same
-- grounding, citations, append-only storage, RLS and retention purge. Only the redacted question is stored.
DO $$
DECLARE c text;
BEGIN
  FOR c IN SELECT conname FROM pg_constraint
           WHERE conrelid = 'ai_analyses'::regclass AND contype = 'c' AND pg_get_constraintdef(oid) LIKE '%use_case%'
  LOOP
    EXECUTE format('ALTER TABLE ai_analyses DROP CONSTRAINT %I', c);
  END LOOP;
END $$;

ALTER TABLE ai_analyses
  ADD COLUMN question  text CHECK (question IS NULL OR char_length(question) <= 1000),
  ADD COLUMN thread_id uuid,
  ADD CONSTRAINT ai_analyses_use_case_check CHECK (use_case IN ('explain','remediation','chat')),
  ADD CONSTRAINT ai_analyses_chat_shape CHECK ((use_case = 'chat') = (question IS NOT NULL AND thread_id IS NOT NULL));

CREATE INDEX ai_analyses_thread ON ai_analyses (thread_id, created_at) WHERE thread_id IS NOT NULL;
