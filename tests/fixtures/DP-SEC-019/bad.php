<?php
/**
 * DP-SEC-019 bad: redirect target from the request.
 *
 * Fixture for tests/run.sh. Lines that must produce a finding end with
 * "// expect: <rule id or PHPCS sniff code>". A good.php must produce no finding at all.
 *
 * @package DP_Security_Standards
 */

/**
 * Payment return: sends the buyer wherever the URL says.
 *
 * @param WP_REST_Request $request Request.
 */
function dp_payment_return( WP_REST_Request $request ) {
	$redirect = esc_url_raw( (string) $request->get_param( 'redirect_to' ) );
	wp_redirect( $redirect ); // expect: dp-sec-019, WordPress.Security.SafeRedirect.wp_redirect_wp_redirect
	exit;
}
