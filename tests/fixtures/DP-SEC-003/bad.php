<?php
/**
 * DP-SEC-003 bad: unauthenticated AJAX and admin-post handlers.
 *
 * Fixture for tests/run.sh. Lines that must produce a finding end with
 * "// expect: <rule id or PHPCS sniff code>". A good.php must produce no finding at all.
 *
 * @package DP_Security_Standards
 */

add_action( 'wp_ajax_nopriv_dp_save_lead', 'dp_save_lead' ); // expect: dp-sec-003
add_action( 'admin_post_nopriv_dp_payment_return', 'dp_payment_return' ); // expect: dp-sec-003

$dp_action = 'dp_vote';
add_action( 'wp_ajax_nopriv_' . $dp_action, 'dp_vote' ); // expect: dp-sec-003

/**
 * Double-quoted hook name after a closure.
 */
function dp_register_public_handlers() {
	$ids = array_map( fn( $x ) => (int) $x, array( 1 ) );
	add_action( "wp_ajax_nopriv_dp_export", 'dp_export' ); // expect: dp-sec-003
	return $ids;
}
