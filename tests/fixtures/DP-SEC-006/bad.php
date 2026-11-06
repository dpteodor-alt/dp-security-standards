<?php
/**
 * DP-SEC-006 bad: request and cookie data unserialized.
 *
 * Fixture for tests/run.sh. Lines that must produce a finding end with
 * "// expect: <rule id or PHPCS sniff code>". A good.php must produce no finding at all.
 *
 * @package DP_Security_Standards
 */

/**
 * Restores a cart from a cookie.
 *
 * @return mixed
 */
function dp_restore_cart() {
	if ( empty( $_COOKIE['dp_cart'] ) ) {
		return array();
	}
	return maybe_unserialize( base64_decode( sanitize_text_field( wp_unslash( $_COOKIE['dp_cart'] ) ) ) ); // expect: dp-sec-006
}

/**
 * Imports settings from the request body.
 *
 * @param WP_REST_Request $request Request.
 * @return mixed
 */
function dp_import( WP_REST_Request $request ) {
	return unserialize( $request->get_body() ); // expect: dp-sec-006
}
