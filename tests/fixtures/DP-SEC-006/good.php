<?php
/**
 * DP-SEC-006 good: JSON instead of PHP serialization.
 *
 * Fixture for tests/run.sh. Lines that must produce a finding end with
 * "// expect: <rule id or PHPCS sniff code>". A good.php must produce no finding at all.
 *
 * @package DP_Security_Standards
 */

/**
 * Restores a cart from a JSON cookie.
 *
 * @return array
 */
function dp_restore_cart() {
	$raw  = isset( $_COOKIE['dp_cart'] ) ? sanitize_text_field( wp_unslash( $_COOKIE['dp_cart'] ) ) : '';
	$cart = json_decode( $raw, true );
	return is_array( $cart ) ? array_map( 'absint', $cart ) : array();
}

/**
 * Legacy import: objects are never instantiated.
 *
 * @param WP_REST_Request $request Request.
 * @return mixed
 */
function dp_import_legacy( WP_REST_Request $request ) {
	return unserialize( $request->get_body(), array( 'allowed_classes' => false ) );
}
