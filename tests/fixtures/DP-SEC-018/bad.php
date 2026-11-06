<?php
/**
 * DP-SEC-018 bad: signatures and tokens compared with == / strcmp.
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
	if ( '' === $signature || $signature !== $expected_signature ) { // expect: dp-sec-018
		return false;
	}
	return 0 === strcmp( (string) $request->get_param( 'token' ), (string) get_option( 'dp_webhook_token' ) ); // expect: dp-sec-018
}
