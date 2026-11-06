<?php
/**
 * DP-SEC-018 good: hash_equals for every secret comparison.
 *
 * Fixture for tests/run.sh. Lines that must produce a finding end with
 * "// expect: <rule id or PHPCS sniff code>". A good.php must produce no finding at all.
 *
 * @package DP_Security_Standards
 */

/**
 * Verifies a payment provider webhook.
 *
 * @param WP_REST_Request $request Request.
 * @return bool
 */
function dp_verify_webhook( WP_REST_Request $request ) {
	$expected_signature = hash_hmac( 'sha256', $request->get_body(), DP_WEBHOOK_SECRET );
	$signature          = (string) $request->get_header( 'X-DP-Signature' );
	if ( '' === $signature || ! hash_equals( $expected_signature, $signature ) ) {
		return false;
	}
	return hash_equals( (string) get_option( 'dp_webhook_token' ), (string) $request->get_param( 'token' ) );
}

/**
 * Not secret comparisons: types, counts, constants.
 *
 * @param string $token_type   Token type.
 * @param int    $tokens_count Count.
 * @param int    $max_tokens   Limit.
 * @return bool
 */
function dp_token_shape( $token_type, $tokens_count, $max_tokens ) {
	return DP_Auth::BEARER === $token_type && $tokens_count === $max_tokens;
}
