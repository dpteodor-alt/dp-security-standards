<?php
/**
 * DP-SEC-019 good: wp_validate_redirect + wp_safe_redirect.
 *
 * Fixture for tests/run.sh. Lines that must produce a finding end with
 * "// expect: <rule id or PHPCS sniff code>". A good.php must produce no finding at all.
 *
 * @package DP_Security_Standards
 */

/**
 * Payment return: only local or allowed hosts, with a fixed fallback.
 *
 * @param WP_REST_Request $request Request.
 */
function dp_payment_return( WP_REST_Request $request ) {
	$target = wp_validate_redirect( esc_url_raw( (string) $request->get_param( 'redirect_to' ) ), home_url( '/thank-you/' ) );
	wp_safe_redirect( $target );
	exit;
}
