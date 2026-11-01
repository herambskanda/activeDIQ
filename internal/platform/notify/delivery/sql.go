package delivery

// The statements of the Dispatcher, each a whole constant over bound parameters (safe-primitives
// P5): nothing here is assembled from data at run time. cols is the one column list every
// statement that returns a Delivery shares, and scan reads it.

const cols = `id::text, purpose, template_version, variables, recipient_account::text, recipient_address, source_kind, source_id,
	requested_by, require_internal, state, attempts, max_attempts, next_attempt_at, last_error_code, provider_message_id, sent_at, created_at`

// sqlClaimDue claims up to $3 due Deliveries of tenant $1 for $2 seconds, raising attempts.
const sqlClaimDue = `UPDATE public.notify_deliveries SET attempts = attempts + 1, lease_until = now() + make_interval(secs => $2), updated_at = now()
	WHERE (tenant_id, id) IN (
	  SELECT tenant_id, id FROM public.notify_deliveries
	  WHERE tenant_id = $1::uuid AND state IN ('queued', 'failed') AND next_attempt_at <= now()
	    AND (lease_until IS NULL OR lease_until < now()) AND attempts < max_attempts
	  ORDER BY next_attempt_at, id LIMIT $3 FOR UPDATE SKIP LOCKED)
	RETURNING ` + cols

// sqlCloseExhausted gives up a Delivery whose last claimed attempt was never recorded; $2 is the code.
const sqlCloseExhausted = `UPDATE public.notify_deliveries SET state = 'given_up', next_attempt_at = NULL, lease_until = NULL,
	last_error_code = $2, updated_at = now()
	WHERE tenant_id = $1::uuid AND state IN ('queued', 'failed') AND attempts >= max_attempts AND (lease_until IS NULL OR lease_until < now())
	RETURNING ` + cols

// sqlRecordSent records a sent attempt: $2 id, $3 provider message id, $4 the claimed attempts.
const sqlRecordSent = `UPDATE public.notify_deliveries SET state = 'sent', next_attempt_at = NULL, lease_until = NULL,
	last_error_code = NULL, provider_message_id = $3, sent_at = now(), updated_at = now()
	WHERE tenant_id = $1::uuid AND id = $2::uuid AND attempts = $4 AND state IN ('queued', 'failed') RETURNING ` + cols

// sqlRecordGivenUp records a final failure: $2 id, $3 error code, $4 the claimed attempts.
const sqlRecordGivenUp = `UPDATE public.notify_deliveries SET state = 'given_up', next_attempt_at = NULL, lease_until = NULL,
	last_error_code = $3, updated_at = now()
	WHERE tenant_id = $1::uuid AND id = $2::uuid AND attempts = $4 AND state IN ('queued', 'failed') RETURNING ` + cols

// sqlRecordFailed records a retryable failure: $2 id, $3 error code, $4 backoff seconds, $5 the claimed attempts.
const sqlRecordFailed = `UPDATE public.notify_deliveries SET state = 'failed', lease_until = NULL, last_error_code = $3,
	next_attempt_at = now() + make_interval(secs => $4), updated_at = now()
	WHERE tenant_id = $1::uuid AND id = $2::uuid AND attempts = $5 AND state IN ('queued', 'failed') RETURNING ` + cols

// sqlInsert queues a Delivery for the current tenant; no row comes back when the dedup key exists.
const sqlInsert = `INSERT INTO public.notify_deliveries
		(tenant_id, dedup_key, purpose, template_version, variables, recipient_kind, recipient_account, recipient_address,
		 source_kind, source_id, requested_by, require_internal, state, max_attempts, next_attempt_at)
		VALUES (NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1, $2, $3, $4::jsonb, $5, $6::uuid, $7, $8, $9, $10, $11, 'queued', $12, now())
		ON CONFLICT (tenant_id, dedup_key) DO NOTHING
		RETURNING ` + cols

// sqlByDedupKey reads the Delivery that holds dedup key $1.
const sqlByDedupKey = `SELECT ` + cols + ` FROM public.notify_deliveries
	WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND dedup_key = $1`

// sqlLatestForSource reads the newest live Delivery of source $1/$2 to account $3.
const sqlLatestForSource = `SELECT ` + cols + ` FROM public.notify_deliveries
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
		  AND source_kind = $1 AND source_id = $2 AND recipient_account = $3::uuid AND state <> 'given_up'
		ORDER BY created_at DESC, id DESC LIMIT 1`

// sqlByID reads Delivery $1.
const sqlByID = `SELECT ` + cols + ` FROM public.notify_deliveries
	WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND id = $1::uuid`
