ALTER DOMAIN sm_identity.email_address ADD CONSTRAINT chk_email CHECK (length(VALUE) > 3);
